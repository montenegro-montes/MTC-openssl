"""Offline image dependency checks; Docker is always mocked."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from campaigns.common import image_chain


class ImageChainTests(unittest.TestCase):
    def resolve(self, target, images=None, fail=False):
        images = {} if images is None else images
        commands = []

        def build(command, **kwargs):
            commands.append(command)
            if fail:
                raise subprocess.CalledProcessError(1, command)
            tag = command[command.index('-t') + 1]
            name, spec = next((n, s) for n, s in image_chain.SPECS.items() if s[0] == tag)
            parent = spec[2]
            layers = images[image_chain.SPECS[parent][0]]['RootFS']['Layers'] if parent else []
            images[tag] = {'Id': 'sha256:' + name, 'RootFS': {'Layers': layers + [name]}}

        with patch.object(image_chain, 'inspect', side_effect=images.get), patch.object(
                image_chain.subprocess, 'run', side_effect=build):
            result = image_chain.ensure(target)
        return result, images, commands

    def test_clean_mutual_install(self):
        result, _, commands = self.resolve('mutual')
        self.assertEqual([r['name'] for r in result['rebuilt']], ['lab', 'mtc', 'profile', 'mutual'])
        self.assertEqual(len(commands), 4)

    def test_clean_network_install(self):
        result, _, _ = self.resolve('network')
        self.assertEqual([r['name'] for r in result['rebuilt']],
                         ['lab', 'mtc', 'profile', 'network-measurement', 'network'])

    def test_reuse(self):
        _, images, _ = self.resolve('mutual')
        result, _, commands = self.resolve('mutual', images)
        self.assertEqual(commands, [])
        self.assertEqual(result['rebuilt'], [])

    def test_changed_parent_refreshes_children(self):
        _, images, _ = self.resolve('mutual')
        images['mt-tls-mtc:local']['RootFS']['Layers'] = ['lab', 'changed-mtc']
        result, _, _ = self.resolve('mutual', images)
        self.assertEqual([r['name'] for r in result['rebuilt']], ['profile', 'mutual'])
        self.assertTrue(all(r['reason'] == 'base image changed' for r in result['rebuilt']))

    def test_failure_stops_chain(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.resolve('profile', fail=True)

    def test_shell_catalog_matches_graph_and_recipes(self):
        result = subprocess.check_output(['bash', '-c',
            'source bin/lib/image-catalog.sh; for i in "${!IMAGES[@]}"; do '
            'printf "%s|%s|%s\\n" "${IMAGES[i]}" "${FILES[i]}" "${PARENTS[i]}"; done'],
            cwd=image_chain.REPO, text=True)
        rows = [r.split('|') for r in result.splitlines()]
        self.assertEqual(len(rows), len(image_chain.SPECS))
        for tag, recipe, index in rows:
            spec = next(s for s in image_chain.SPECS.values() if s[0] == tag)
            self.assertEqual(spec[1], recipe)
            parent = rows[int(index)][0] if int(index) >= 0 else None
            self.assertEqual(parent, image_chain.SPECS[spec[2]][0] if spec[2] else None)
            self.assertTrue((image_chain.REPO / recipe).is_file())
            if parent:
                text = (image_chain.REPO / recipe).read_text()
                self.assertTrue('FROM ' + parent in text or 'MTC_BASE_IMAGE=' + parent in text)

    def test_shell_launchers_install_and_reuse_without_fixtures(self):
        stubs = r'''set -euo pipefail
source bin/lib/image-catalog.sh
STATE="$1/state"; MOCK_IMAGES="$1/images"; BUILDS="$1/builds"
MT_PREPARE_EVENTS="$1/events"
mkdir -p "$STATE" "$MOCK_IMAGES"
: > "$BUILDS"; : > "$MT_PREPARE_EVENTS"
fail() { echo "$*" >&2; exit 1; }
mt_compose_ready() { :; }
mt_docker_ready() { :; }
python_ready() { :; }
configure_paths() { :; }
prepare_fixtures() { fail 'unexpected fixture generation'; }
mt_image_required() { test -f "$MOCK_IMAGES/$1"; }
mt_image_matches_parent() { mt_image_required "$2"; }
docker() {
 if [[ "$1 $2" == 'image inspect' ]]; then
  test -f "$MOCK_IMAGES/$3"
 elif [[ "$1" == build ]]; then
  local tag=$5
  touch "$MOCK_IMAGES/$tag"
  printf '%s\n' "$tag" >> "$BUILDS"
 else
  fail "unexpected Docker command: $*"
 fi
}
'''
        for launcher, start, end, command in (
            ('bin/base/mt-prepare', 'prepare() (', '\nmenu()', 'prepare 7 no'),
            ('bin/containers/mt-install', 'build_stage() {', '\ncleanup()', 'install_stages ALL'),
        ):
            with self.subTest(launcher=launcher), tempfile.TemporaryDirectory() as tmp:
                text = (image_chain.REPO / launcher).read_text()
                functions = text[text.index(start):text.index(end)]
                script = stubs + functions + '\n' + command + '\n' + command + '\n'
                subprocess.run(['bash', '-c', script, '_', tmp], cwd=image_chain.REPO,
                               check=True, capture_output=True, text=True)
                self.assertEqual((Path(tmp) / 'builds').read_text().splitlines(),
                    ['mt-tls-lab:local', 'mt-tls-mtc:local', 'mt-tls-capture:local',
                     'mt-tls-mtc-profile:local', 'mt-tls-mtc-mutual:local',
                     'mt-tls-network-measurement:local', 'mt-tls-network:local'])


if __name__ == '__main__':
    unittest.main()

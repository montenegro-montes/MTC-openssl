import argparse
import hashlib
from pathlib import Path
from .adapters import load, digest
from .render import render

def main():
    parser=argparse.ArgumentParser(description='Render existing evidence as offline HTML; no measurements or statistical analysis.')
    parser.add_argument('directory',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        model=load(args.directory)
        repo=Path(__file__).resolve().parents[3]
        source=model['source']
        identifier=source.name+'-'+hashlib.sha256(str(source).encode()).hexdigest()[:8]
        output=(args.output or repo/'artifacts/reports'/identifier/'report.html').resolve()
        if output==source or source in output.parents: raise ValueError('Output must be outside the source results directory')
        if output.suffix.lower()!='.html': raise ValueError('Output must be an HTML file')
        if output.exists(): raise ValueError('Output already exists; choose another output path')
        content=render(model)
        for record in model['inventory']:
            if digest(source/record['artifact'])!=record['sha256']: raise ValueError('Source changed during rendering')
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('x') as stream: stream.write(content)
        print(output)
    except (ValueError,OSError) as error: parser.exit(1,f'ERROR: {error}\n')

if __name__=='__main__': main()

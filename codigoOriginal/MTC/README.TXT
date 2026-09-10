

## STEPS
1. Set up environment variables in .env file as you wish
2. Build and run the container with docker compose from the directory where docker-compose.yaml is
    - cd path/to/docker-compose.yaml
    - docker compose up -d
3. Connect to the running container if you wish to inspect something
    - docker exec ${CONTAINER_NAME} -it bash

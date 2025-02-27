#!/bin/bash
# docker compose ps
#docker compose exec -it mitm /code/mitm/switch/switch  & # Runs already in start-up
docker compose exec -it go-processor go run main.go &
docker compose exec -it sec ping insec &
docker compose logs -f 

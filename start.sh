docker build -t hektor-api .
docker run --env-file .env -p 5000:5000 hektor-api
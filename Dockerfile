FROM python:3.9

COPY . /app

WORKDIR /app

RUN pip install https://github.com/PaulSec/API-dnsdumpster.com/archive/master.zip --user
RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]

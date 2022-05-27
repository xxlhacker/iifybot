FROM registry.fedoraproject.org/fedora-minimal:34

RUN microdnf install -y python3.9 wkhtmltopdf

WORKDIR /usr/src/app

COPY . /usr/src/app/

RUN pip3 install --no-cache-dir --upgrade pip pipenv && \
    pipenv lock --requirements > requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "./main.py"]

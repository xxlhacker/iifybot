FROM registry.access.redhat.com/ubi8/ubi-minimal

RUN microdnf install -y rpm which wget python3.9 libpng15 compat-openssl10 libpng libjpeg openssl icu libX11 libXext libXrender xorg-x11-fonts-Type1 xorg-x11-fonts-75dpi

RUN wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox-0.12.6-1.centos7.x86_64.rpm

RUN rpm -ivh wkhtmltox-0.12.6-1.centos7.x86_64.rpm

WORKDIR /usr/src/app

COPY . /usr/src/app/

RUN mv /usr/src/app/fonts/* /usr/share/fonts

RUN pip3 install --no-cache-dir --upgrade pip pipenv && \
    pipenv requirements > requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "./main.py"]

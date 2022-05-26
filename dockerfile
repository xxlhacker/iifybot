FROM registry.access.redhat.com/ubi8/python-39

# RUN dnf install -y python39 python38-pip wget xorg-x11-fonts-75dpi xorg-x11-fonts-Type1 libpng libjpeg openssl icu libX11 libXext libXrender

RUN dnf install -y python39 python38-pip wget

RUN wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox-0.12.6-1.centos8.x86_64.rpm

RUN rpm -ivh wkhtmltox-0.12.6-1.centos8.x86_64.rpm

COPY . .

RUN pip3 install --no-cache-dir --upgrade pip pipenv && \
    pipenv lock --requirements > requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 5000





#7 0.227    fontconfig is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64                                           
#7 0.227    freetype is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64                                             
#7 0.227 	libX11 is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64
#7 0.227 	libXext is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64
#7 0.227 	-- libXrender is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64
#7 0.227 	-- libjpeg is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64
#7 0.227 	libpng is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64
#7 0.227 	openssl is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64
#7 0.227 	-- xorg-x11-fonts-75dpi is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64
#7 0.227 	-- xorg-x11-fonts-Type1 is needed by wkhtmltox-1:0.12.6-1.centos8.x86_64

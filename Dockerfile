FROM smadnet/base

#? Install necessary packages for the module

#? Copy files to docker
ADD . /module
WORKDIR /module

#? Install radare2
RUN dpkg -i radare2_5.7.8_amd64.deb
RUN apt-get update
RUN apt-get install -y radare2

#? Install requirements python libraries for the module
RUN pip3 install -r requirements.txt

#? Then run the module
CMD ["python3", "-u", "run.py"]
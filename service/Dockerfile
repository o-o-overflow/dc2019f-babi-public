from ubuntu:18.04
run echo "travis_fold:start:Dapt\033[33;1mservice Dockerfile apt\033[0m" && \
    apt-get -qq update && apt-get install -qq libssl-dev python-pip libffi-dev g++ linux-headers-generic make bash && \
    echo "\ntravis_fold:end:Dapt\r"

run echo "travis_fold:start:DIpip\033[33;1minteractions Dockerfile pip\033[0m" && \
    pip install pwntools && \
    echo "\ntravis_fold:end:DIpip\r"

copy babi /babi
copy babi /babi.orig
# Currently anything that goes in public files must be pre-built and checked in git
# Can still build other things locally though
#run clang -std=gnu99 -o /service /service.c \
#    && rm /service.c \
#    && apt-get -y purge clang \
#    && apt-get -y autoremove

# The flagbot will periodically echo the flag > this file (flag_path in info.yaml)
run touch /flag && chmod 644 /flag && echo "OOO{this is a test flag}" > /flag

expose 47793
cmd chmod go-rwx /proc && /babi

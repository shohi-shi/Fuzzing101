PROGRAM_NAME = xpdf
VERSION = 3.02
SEED = 123

.PHONY: all clean dashboard fuzz

all: clean build build-afl

configure:
	@echo "sudo apt-get update && sudo apt-get upgrade -y" > $@
	@echo "sudo apt-get install -y screen build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools lld llvm llvm-dev clang" >> $@
	@echo "if [[ $(gcc --version) ]]; then sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev; else (echo "Config-Error: gcc is missing!" > /dev/stderr; exit 1); fi" >> $@
	@echo "cd $HOME && git clone https://github.com/AFLplusplus/AFLplusplus" >> $@
	@echo "cd $HOME/AFLplusplus && export LLVM_CONFIG="llvm-config-11" && make distrib && sudo make install" >> $@
	@sudo chmod +x $@
	@echo "Installing dependencies..."
	./$@

build: configure
	@echo "Building Xpdf..."
	@if [ -d $HOME/${PROGRAM_NAME}/ ]; then (sudo rm -rf $HOME/${PROGRAM_NAME}/*); else (mkdir $HOME/${PROGRAM_NAME}) fi
	@echo "project dir: $HOME/${PROGRAM_NAME}/"
	@echo "source dir: $HOME/${PROGRAM_NAME}/src/"
	@echo "build dir: $HOME/${PROGRAM_NAME}/$@/"
	@cd $HOME/${PROGRAM_NAME}/ && wget https://dl.xpdfreader.com/old/xpdf-${VERSION}.tar.gz -O tmp.tar.gz
	@cd $HOME/${PROGRAM_NAME}/ && tar -xvf $HOME/${PROGRAM_NAME}/tmp.tar.gz && sudo rm -rf $HOME/${PROGRAM_NAME}/tmp.tar.gz && sudo mv $HOME/${PROGRAM_NAME}/xpdf-{VERSION}/ src
	@if [ -d $HOME/${PROGRAM_NAME}/$@ ]; then (sudo rm -rf $HOME/${PROGRAM_NAME}/$@/*); else (mkdir $HOME/${PROGRAM_NAME}/$@); fi
	@cd $HOME/${PROGRAM_NAME}/src && CC="clang" CXX="clang++" CFLAGS="-fsanitize=address -g -O0" CXXFLAG="-fsanitize=address -g -O0" LDFLAGS="-fsanitize=address -g -O0" ./configure --prefix=$HOME/${PROGRAM_NAME}/$@ --disable-shared && make && make install
	@echo "Build complete!"

samples:
	@mkdir -p $HOME/${PROGRAM_NAME}/$@/
	@cd $HOME/${PROGRAM_NAME}/$@/ && wget https://github.com/mozilla/pdf.js-sample-files/raw/master/helloworld.pdf -O 1.pdf
	@cd $HOME/${PROGRAM_NAME}/$@/ && wget http://www.africau.edu/images/default/sample.pdf -O 2.pdf
	@cd $HOME/${PROGRAM_NAME}/$@/ && wget https://www.melbpc.org.au/wp-content/uploads/2017/10/small-example-pdf-file.pdf -O 3.pdf

optimized: samples
	@mkdir -p $HOME/${PROGRAM_NAME}/$@/

build-afl: configure
	@echo "Building xpdf with AFL..."
	@if [ -d $HOME/${PROGRAM_NAME}/$@ ]; then (sudo rm -rf $HOME/${PROGRAM_NAME}/$@/*); else (mkdir $HOME/${PROGRAM_NAME}/$@) fi
	@cd $HOME/${PROGRAM_NAME}/src && CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ CFLAGS="-fsanitize=address -g -O0" CXXFLAG="-fsanitize=address -g -O0" LDFLAGS="-fsanitize=address -g -O0" ./configure --prefix=$HOME/${PROGRAM_NAME}/$@ --disable-shared && make && make install
	@echo "Build xpdf with ALF complete!"

fuzz: optimized build-afl
	@echo "Fuzzing..."
	@if [ -d $HOME/${PROGRAM_NAME}/results ]; then (echo "ALF output dir: $HOME/${PROGRAM_NAME}/results/"); else (mkdir $HOME/${PROGRAM_NAME}/results && echo "AFL output dir: $HOME/${PROGRAM_NAME}/results/") fi
	@if [ -d $HOME/${PROGRAM_NAME}/output ]; then (echo "output dir: $HOME/${PROGRAM_NAME}/output/"); else (mkdir $HOME/${PROGRAM_NAME}/output && echo "output dir: $HOME/${PROGRAM_NAME}/output/") fi
	screen -dmS ${PROGRAM_NAME}-main -- afl-fuzz -M main-$HOSTNAME -i $HOME/${PROGRAM_NAME}/samples/ -o $HOME/${PROGRAM_NAME}/results/ -s ${SEED} -- $HOME/${PROGRAM_NAME}/build-afl/bin/pdftotext @@ $HOME/${PROGRAM_NAME}/output
	@echo "Fuzz setup successfully!"

dashboard: fuzz
	@screen -r ${PROGRAM_NAME}-main

clean:
	@if [ -d $HOME/${PROGRAM_NAME}/ ]; then rm -rf $HOME/${PROGRAM_NAME}/; fi
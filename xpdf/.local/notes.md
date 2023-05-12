Exploit POC for CVE-2019-13288 in XPDF 3.02
-----------------------------------------------------------------------------------------
CVE-2019-13288 is a vulnerability that may cause an infinite recursion via a crafted file.

Since each called function in a program allocates a stack frame on the stack, if a a function is recursively called so many times it can lead to stack memory exhaustion and program crash.

As a result, a remote attacker can leverage this for a DoS attack.

You can find more information about Uncontrolled Recursion vulnerabilities at the following link: https://cwe.mitre.org/data/definitions/674.html
-----------------------------------------------------------------------------------------
Goals for this exercise is:
    - Compiling a target application with instrumentation
    - Running a fuzzer (afl-fuzz)
    - Triaging crashes with a debugger (GDB)
-----------------------------------------------------------------------------------------
Prerequisite Libs:
    - CMake 2.8.8 or newer
        ```sh
        if [[ $(cmake --version) ]]; then echo "cmake version $(cmake --version | grep -Eo '[0-9]\.[0-9]+\.[0-9]+') is already installed!"; else sudo apt-get install -y cmake; fi
        ```
    - FreeType 2.0.5 or newer
        ```sh
        if [[ $(make -v) ]]; then echo "make version $(make -v | grep -Eo '[0-9]\.[0-9]+\.[0-9]+' | head -1) is already installed!"; else sudo apt-get install -y build-essential; fi
        cd $HOME && git clone https://github.com/freetype/freetype.git && cd $HOME/freetype/ && mkdir install
        sudo apt-get install -y libtool
        if [[ $(pkg-config --modversion libpng) ]]; then echo "libpng is already installed!"; else echo "Error: Install libpng!"; fi
        if [[ $(pkg-config --modversion zlib) ]]; then echo "zlib is already installed!"; else echo "Error: Install zlib!"; fi
        if [[ $(pkg-config --modversion brotli) ]]; then echo "brotli is already installed!"; else echo "Error: Install brotli!"; fi
        if [[ $(pkg-config --modversion gzip) ]]; then echo "gzip is already installed!"; else echo "Error: Install gzip!"; fi
        if [[ $(pkg-config --modversion bzip2) ]]; then echo "bzip2 is already installed!"; else echo "Error: Install bzip2!"; fi
        ./autogen.sh
        ./configure
        make
        make install
        ```
    - Qt 4.8.x or 5.x (for xpdf only)
        ```sh
        sudo apt-get install qt5-default -y
        ```
    - libpng (for pdftoppm and pdftohtml, Prerequisite lib for FreeType)
        ```sh
        sudo apt-get install libpng-dev -y
        ```
    - zlib (for pdftoppm and pdftohtml, Prerequisite lib for FreeType)
        ```sh
        sudo apt-get install zlib1g zlib1g-dev -y
        ```
    - brotli (Prerequisite lib for FreeType)
        ```sh
        sudo apt-get install brotli -y
        ```
    - Gzip (Prerequisite lib for FreeType)
        ```sh
        sudo apt-get install gzip -y
        ```
    - bzip2 (Prerequisite lib for FreeType)
        ```sh
        sudo apt-get install bzip2 -y
        ```
    - t1lib (for xpdf)
        ```sh
        sudo apt-get install -y t1lib-bin
        ```
    - motif (for xpdf)
        ```sh
        sudo apt-get install -y libmotif-dev
        ```
Steps:
    ```sh
    PROGRAM_NAME="xpdf"
    PROGRAM_VERSION=3.02
    sudo apt-get update && sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
    sudo apt-get install -y lld llvm llvm-dev clang <!-- sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 -->
    sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
    mkdir $HOME/${PROGRAM_NAME} && cd $HOME/${PROGRAM_NAME}/
    wget https://dl.xpdfreader.com/old/xpdf-${PROGRAM_VERSION}.tar.gz -O xpdf.tar.gz
    tar -xvzf xpdf.tar.gz && sudo rm -r xpdf.tar.gz && sudo mv xpdf-{PROGRAM_VERSION}/ bin && cd bin
    ./configure --prefix="$HOME/${PROGRAM_NAME}/build" && make && make install && cd ..
    mkdir examples && cd examples
    wget https://github.com/mozilla/pdf.js-sample-files/raw/master/helloworld.pdf -O 1.pdf
    wget http://www.africau.edu/images/default/sample.pdf -O 2.pdf
    wget https://www.melbpc.org.au/wp-content/uploads/2017/10/small-example-pdf-file.pdf -O 3.pdf
    cd $HOME && git clone https://github.com/AFLplusplus/AFLplusplus
    cd AFLplusplus && export LLVM_CONFIG="llvm-config-11"
    make distrib
    sudo make install
    cd $HOME/${PROGRAM_NAME}/bin && make clean && CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/${PROGRAM_NAME}/afl-build/" && make && make install
    afl-fuzz -i $HOME/${PROGRAM_NAME}/examples/ -o $HOME/${PROGRAM_NAME}/results/ -s 123 -- $HOME/${PROGRAM_NAME}/afl-build/bin/pdftotext @@ $HOME/${PROGRAM_NAME}/output
    ```
Rebuild cmd:
    ```sh
    sudo rm -rfv $HOME/${PROGRAM_NAME}/build/
    cd $HOME/${PROGRAM_NAME}/bin/ && make clean && CC="clang" CXX="clang++" CFLAGS="-fsanitize=address -g -O0" CXXFLAG="-fsanitize=address -g -O0" LDFLAGS="-fsanitize=address -g -O0" ./configure --prefix="$HOME/${PROGRAM_NAME}/build/" && make && make install && cd $HOME/${PROGRAM_NAME}
    ```

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
Required Libs:
    - CMake 2.8.8 or newer
    - FreeType 2.0.5 or newer
    - Qt 4.8.x or 5.x (for xpdf only)
    - libpng (for pdftoppm and pdftohtml)
    - zlib (for pdftoppm and pdftohtml)
Steps:
    - program_name="xpdf"
    - program_version=3.02
    - sudo apt-get update && sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
    - sudo apt-get install -y lld llvm llvm-dev clang <!-- sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 -->
    - sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
    - mkdir $HOME/${program_name} && cd $HOME/${program_name}/
    - wget https://dl.xpdfreader.com/old/xpdf-${program_version}.tar.gz -O xpdf.tar.gz
    - tar -xvzf xpdf.tar.gz && sudo rm -r xpdf.tar.gz && sudo mv xpdf-{program_version}/ bin && cd bin
    - ./configure --prefix="$HOME/${program_name}/build" && make && make install && cd ..
    - mkdir examples && cd examples
    - wget https://github.com/mozilla/pdf.js-sample-files/raw/master/helloworld.pdf -O 1.pdf
    - wget http://www.africau.edu/images/default/sample.pdf -O 2.pdf
    - wget https://www.melbpc.org.au/wp-content/uploads/2017/10/small-example-pdf-file.pdf -O 3.pdf
    - cd $HOME && git clone https://github.com/AFLplusplus/AFLplusplus
    - cd AFLplusplus && export LLVM_CONFIG="llvm-config-11"
    - make distrib
    - sudo make install
    - cd $HOME/${program_name}/bin && make clean && CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/${program_name}/afl-build/" && make && make install
    - afl-fuzz -i $HOME/${program_name}/examples/ -o $HOME/${program_name}/results/ -s 123 -- $HOME/${program_name}/afl-build/bin/pdftotext @@ $HOME/${program_name}/output
Rebuild cmd:
    - sudo rm -rfv $HOME/${program_name}/build/ && cd $HOME/${program_name}/bin/ && make clean && CC="clang" CXX="clang++" CFLAGS="-fsanitize=address -g -O0" CXXFLAG="-fsanitize=address -g -O0" ./configure --prefix="$HOME/${program_name}/build/" && make && make install && cd $HOME/${program_name}

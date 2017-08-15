#!/bin/bash

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
    # brew install --force openssl
    cd src

    # Build with AVX
    ./configure --disable-native-tests CPPFLAGS='-mavx -I/usr/local/opt/openssl/include -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-sse4.1\""' LDFLAGS="-L/usr/local/opt/openssl/lib"
    make -sj4
    mv ../run/john ../run/john-avx
    make clean; make distclean

    # Build with AVX2
    ./configure --disable-native-tests CPPFLAGS='-mavx2 -I/usr/local/opt/openssl/include -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-avx\""' LDFLAGS="-L/usr/local/opt/openssl/lib"
    make -sj4
    mv ../run/john ../run/john-avx2
    make clean; make distclean

    # Build with SSE4.1 ("widely" compatible binary)
    ./configure --disable-native-tests CPPFLAGS='-I/usr/local/opt/openssl/include' LDFLAGS="-L/usr/local/opt/openssl/lib"
    make -sj4
    mv ../run/john ../run/john-sse4.1

    mv ../run/john-avx2 ../run/john  # call the most feature-rich binary 'john'

    # ./configure CPPFLAGS="-I/usr/local/opt/openssl/include" LDFLAGS="-L/usr/local/opt/openssl/lib"
    # make -sj4

    # ../.travis/test.sh

    cd ..
    rm -rf run/ztex

    echo "These macOS Sierra builds require OpenSSL and GMP. To install these dependencies, run 'brew install --force openssl gmp' command." > README-macOS.txt
    zip -y -r JtR-macOS.zip run/ doc/ README.md README README-jumbo README-macOS.txt

elif [[ -z "$TEST" ]]; then
    cd src

    # Build and run with the address sanitizer instrumented code
    export ASAN_OPTIONS=symbolize=1
    export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)

    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get install libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev
    sudo apt-get install fglrx-dev opencl-headers || true

    # Configure and build
    ./configure $ASAN
    make -sj4

    ../.travis/test.sh

elif [[ "$TEST" == "no OpenMP" ]]; then
    cd src

    # Build and run with the address sanitizer instrumented code
    export ASAN_OPTIONS=symbolize=1
    export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)

    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get install libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev
    sudo apt-get install fglrx-dev opencl-headers || true

    # Configure and build
    ./configure $ASAN --disable-native-tests --disable-openmp
    make -sj4

    ../.travis/test.sh

elif [[ "$TEST" == "fresh test" ]]; then
    # ASAN using a 'recent' compiler
    docker run -v $HOME:/root -v $(pwd):/cwd ubuntu:16.10 sh -c " \
      cd /cwd/src; \
      apt-get update -qq; \
      apt-get install -y build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libbz2-dev; \
      ./configure --enable-asan; \
      make -sj4; \
      export OPENCL="""$OPENCL"""; \
      PROBLEM='slow' ../.travis/test.sh
   "

elif [[ "$TEST" == "TS --restore" ]]; then
    # Test Suite run
    cd src

    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get install libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev

    # Configure and build
    ./configure
    make -sj4

    cd ..
    git clone --depth 1 https://github.com/magnumripper/jtrTestSuite.git tests
    cd tests
    #export PERL_MM_USE_DEFAULT=1
    (echo y;echo o conf prerequisites_policy follow;echo o conf commit)|cpan
    cpan install Digest::MD5
    ./jtrts.pl --restore

elif [[ "$TEST" == "TS docker" ]]; then
    # Test Suite run
    docker run -v $HOME:/root -v $(pwd):/cwd ubuntu:xenial sh -c ' \
      cd /cwd/src; \
      apt-get update -qq; \
      apt-get install -y build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libbz2-dev git; \
      ./configure; \
      make -sj4; \
      cd ..; \
      git clone --depth 1 https://github.com/magnumripper/jtrTestSuite.git tests; \
      cd tests; \
      cpan install Digest::MD5; \
      ./jtrts.pl --restore
    '
else
    echo  "Nothing to do!!"
fi

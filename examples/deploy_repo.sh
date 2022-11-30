#!/bin/bash

curl -k https://repo1.maven.org/maven2/io/netty/netty-transport-native-epoll/4.1.78.Final/netty-transport-native-epoll-4.1.78.Final-linux-x86_64.jar -o netty-transport-native-epoll-4.1.78.Final-linux-x86_64.jar
curl -k https://repo1.maven.org/maven2/io/netty/netty-transport-native-epoll/4.1.78.Final/netty-transport-native-epoll-4.1.78.Final-linux-aarch_64.jar -o netty-transport-native-epoll-4.1.78.Final-linux-aarch_64.jar

mvn deploy:deploy-file -Dfile=netty-transport-native-epoll-4.1.78.Final-linux-x86_64.jar -Durl="file:$(pwd)/test-repo" -DgroupId=io.netty -DartifactId=netty-transport-native-epoll -Dpackaging=jar -Dclassifier=linux-x86_64 -Dversion=4.1.78.Final

mvn deploy:deploy-file -Dfile=netty-transport-native-epoll-4.1.78.Final-linux-aarch_64.jar -Durl="file:$(pwd)/test-repo" -DgroupId=io.netty -DartifactId=netty-transport-native-epoll -Dpackaging=jar -Dclassifier=linux-aarch_64 -Dversion=4.1.78.Final

rm netty-transport-native-epoll-4.1.78.Final-linux-x86_64.jar netty-transport-native-epoll-4.1.78.Final-linux-aarch_64.jar

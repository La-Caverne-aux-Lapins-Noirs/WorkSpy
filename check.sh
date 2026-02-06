#!/bin/sh

echo -n "Validating syntax... "
for file in `find . -name "*.php" 2> /dev/null`; do
    php -l $file > /dev/null || /bin/echo -ne "\n\033[0;31m$file Syntax error\033[00m"
done
echo "done."

for file in `ls tests/*.php`; do
    if [ "$file" = "tests/tools.php" ]; then
	continue
    fi
    OUT=`php $file 2> $file.errors`
    if [ "$?" -eq "0" ];then
        /bin/echo -ne "\033[0;32m"
        rm "$file.errors"
    else
        /bin/echo -ne "\033[0;31m"
        file=`basename $file`
        echo -n $OUT
        OUT="KO $file"
    fi
    echo $OUT
    /bin/echo -ne "\033[00m"
done

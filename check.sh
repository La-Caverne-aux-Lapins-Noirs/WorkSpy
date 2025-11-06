#!/bin/bash

for file in `find . -name "*.php"`; do
    php -l $file
done


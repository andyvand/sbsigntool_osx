#!/bin/sh
for i in $@; do
sbsign --key /etc/secureboot/Clover_Sign_Keys/Signing.key --cert /etc/secureboot/Clover_Sign_Keys/Signing.crt "$i"
if [ -f "$i.signed" ]; then mv "$i.signed" "$i"
fi
done


CODESIGN=codesign

### Change to "" for no signing or "Something: Me..." for signing ###
SIGNCERT="Developer ID Application: Andy Vandijck (GSF3NR4NQ5)"
PKGSIGNCERT="Developer ID Installer: Andy Vandijck (GSF3NR4NQ5)"

installer:
	mkdir -p sbsigntoolpkg
	mkdir -p sbsigntoolcombopkg
	sudo chown -R root:wheel instdir
	cd instdir && sudo rm -f .DS_Store */.DS_Store */*/.DS_Store && sudo cpio -o < ../sbsigntool_pkg.txt > ../sbsigntoolpkg/Payload && sudo rm -f .DS_Store */.DS_Store */*/.DS_Store && sudo mkbom . ../sbsigntoolpkg/Bom && cd ..
	sudo cp -Rf PackageInfo sbsigntoolpkg/PackageInfo
	cd sbsigntoolpkg && sudo rm -Rf .DS_Store && sudo xar -cjf ../sbsigntoolcombopkg/sbsigntool-0.6.pkg . && cd ..
	sudo rm  -Rf sbsigntoolpkg Payload Bom
	if [ $(PKGSIGNCERT) != "" ]; then sudo productsign --sign $(PKGSIGNCERT) sbsigntoolcombopkg/sbsigntool-0.6.pkg sbsigntoolcombopkg/sbsigntool-0.6-apple.pkg && sudo rm -Rf sbsigntoolcombopkg/sbsigntool-0.6.pkg; else mv sbsigntoolcombopkg/sbsigntool-0.6.pkg sbsigntoolcombopkg/sbsigntool-0.6-apple.pkg; fi
	sudo cp -Rf Resources sbsigntoolcombopkg/Resources
	sudo cp -f Distribution sbsigntoolcombopkg/Distribution
	cd sbsigntoolcombopkg &&  sudo rm -Rf .DS_Store */.DS_Store */*/.DS_Store && sudo productbuild --distribution Distribution --resources Resources --package-path $(PWD) ../sbsigntool-apple.pkg && cd ..
	sudo rm -Rf sbsigntoolcombopkg
	if [ $(PKGSIGNCERT) != "" ]; then sudo productsign --sign $(PKGSIGNCERT) sbsigntool-apple.pkg sbsigntool.pkg && sudo rm -Rf sbsigntool-apple.pkg; else mv sbsigntool-apple.pkg sbsigntool.pkg; fi


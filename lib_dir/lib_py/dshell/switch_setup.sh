# set this to the NEXT (not yet published) version
VERSION="5.5"

if [ -z "$1" ]; then
	echo "Usage: $0 [stable | dev]"
	exit 1
fi

function msg {
	echo ""
	echo ">>> $1"
}

case "$1" in
"stable")
	pyfiles=$(find . -name "*.py")

	msg "Changing debug level to WARNING"
	sed -i -r "s/# *(logger.setLevel\(logging.WARNING\))/\1/g;s/^(logger.setLevel\(logging.DEBUG\))/# \1/g" pypacker/__init__.py

	msg "Replacing version numbers"
	sed -i -r "s/version=\".*\"/version=\"$VERSION\"/g" setup.py

	msg "Searching untracked NOT ignored files... did you forget to add anything?"
	git ls-files --others --exclude-from=.gitignore

	msg "Any TODOs open?"
	for pyfile in $pyfiles; do
		grep --color=auto -H "TODO" "$pyfile"
	done

	msg "Non disabled debug output"
	grep --color=auto -ir "^[^#]*logger.debug" --exclude "checksum.py" *

	msg "Raw print calls"
	grep --color=auto -r "print(" --exclude "test_pypacker.py" --exclude "README.md" --exclude "switch_setup.sh"\
		--exclude "sniff_n_dump.py" --exclude "list_packet_classes.py" --exclude-dir "examples" --exclude "can.py"\
		--exclude-dir "docs" --exclude-dir "tests"

	msg "flake8"
	if command -v flake8 &> /dev/null; then
		# flake8 = Wrapper around PyFlakes, pep8 & mccab
		flake8 --config=./qa_config.txt ./pypacker
	else
		echo "Warning: Install flake8"
	fi

	msg "Pylint"
	if command -v pylint &> /dev/null; then
		# Variable names: allow constant name style (all uppercase)
		pylint --rcfile=./qa_config.txt --variable-rgx='([a-z_]+)|([A-Z_]+)' ./pypacker
	else
		echo "Warning: Install Pylint"
	fi

	#if [ "$2" = "rebuilddoc" ]; then
	#	msg "regenerating doc"
	#	export PYTHONPATH=$PYTHONPATH:$(pwd)
	#	rm -rf ./doc
	#	cd ./doc_sphinx_generated
	#	make clean html
	#	cd ..
	#	cp -r ./doc_sphinx_generated/_build/html/ ./doc
	#	git add doc
	#fi

	msg "Header definition: string instead of bytes?"
	grep --color=auto -ir -Po "\"\ds\", *\".+"

	msg "set(...) instead of {...}?"
	grep --color=auto -ir -Po " set\([^\)]"

	msg "Lower case hex numbers/upper case hex strings?"
	for f in $pyfiles; do
		# Hex numbers should be uppercase
		grep --color=auto -H -P "0x[0-9]{0,1}[a-f]{1,2}" $f
		# Hex bytes should be lowercase
		grep --color=auto -H -P "\\\\x[0-9]{0,1}[A-F]{1,2}" $f
	done

	msg "Old style unpack like unpack('H', value)? (non precompiled structs)"
	grep --color=auto -ir -P "unpack\([\"\']" | grep --color=auto  -P ".py:"


	if [ "$2" == "v" ]; then
		msg "re-adding tag 'v$VERSION'"
		git tag --del "v$VERSION" 1>&/dev/null
		# Remove remote tag
		#git push origin :refs/tags/"v$VERSION" 1>&/dev/null
		git tag "v$VERSION"
	fi

	msg "If everything is OK call: git push -u origin master --tags"
	# PyPi upload
	# Source: https://packaging.python.org/tutorials/packaging-projects/#uploading-your-project-to-pypi
	# # Create package in dist/
	# python setup.py sdist
	# # Upload. Chose correct version in dist/
	# python3 -m twine upload --repository-url  https://upload.pypi.org/legacy/ dist/pypacker-...
;;
"dev")
	msg "Changing debug level to DEBUG"
	sed -i -r "s/# *(logger.setLevel\(logging.DEBUG\))/\1/;s/^(logger.setLevel\(logging.WARNING\))/# \1/g" pypacker/__init__.py
;;
esac

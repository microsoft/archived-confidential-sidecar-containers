#
# Make a payload container for repoducing the io error issue
# policy which allows the fragment in.
#
SKRPATH = ../../../../github.com/Microsoft/confidential-sidecar-containers
SKRFILES = $(wildcard $(SKRPATH)/bin/*) $(SKRPATH)/docker/skr/skr.sh $(SKRPATH)/docker/skr/tests/attest_client.sh

all: components container payload.rego.base64 policy

.skr: $(SKRFILES)
	mkdir -p skr
	cp $(SKRFILES) skr
	chmod a+x skr/*.sh
	touch .skr

PHONY: all

%.rego.base64: %.toml .pushed
	/mnt/c/ContainerPlat/securitypolicy.exe -t rego -c $< > $@

# $@ is target, $< prerequisite

%.rego.string64: %.rego.base64
	echo \" > $@
	cat $< >> $@
	echo \" >> $@

%.rego.escaped: %.rego.string64
	tr -d \[\\n\\r\] < $< > $@
	

%.rego: %.rego.base64
	base64 -d $< > $@

components: verbose-report help.txt payload.py help.txt ifaddrs breakit.sh

verbose-report: verbose-report.c
	gcc -O2 -static -s verbose-report.c -o verbose-report

ifaddrs: ifaddrs.c
	gcc -O2 -static -s ifaddrs.c -o ifaddrs

build: Dockerfile components .skr
	docker build -t ${IMAGE} .

push: build
	docker push ${IMAGE}
	touch .pushed


set-uvm-policy.sh: open_door.rego.base64
	cat set-uvm-policy.head open_door.rego.base64 | tr -d \[\\n\\r\] > $@


container: build push

policy: open_door.rego
	cat ../pod.head open_door.rego.escaped ../pod.tail > ../pod.json
	cat ../pod.head.snp open_door.rego.escaped ../pod.tail > ../pod.snp.json

gfi: build push useful .skr set-uvm-policy.sh payload.rego.base64 hacked.rego
	echo
	cat set-uvm-policy.sh
	echo
	echo
	echo "don't forget to copy the pod.snp.json and do a pull on the snp box!"
 

../pod.snp.json: policy

../pod.json: policy

login:
	az acr login -n ${REGISTRY}

info:
	echo REGISTRY ${REGISTRY}
	echo IMAGE ${IMAGE}
	echo SKRFILES $(SKRFILES)
	ls $(SKRPATH)

clean:
	rm -f payload.rego.base64 payload.rego verbose-report payload.rego.escaped payload.rego.string64

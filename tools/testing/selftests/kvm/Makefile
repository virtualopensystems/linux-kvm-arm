ARCHS = arm

all run_tests clean:
	for a in $(ARCHS); do make -C $$a $@; done

run_tests: all

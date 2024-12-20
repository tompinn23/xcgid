ARCH ?= $(shell uname -m)
build_dir := build/$(ARCH)

include rules.mk

.PHONY: clean

all: bin/xcgid bin/child bin/libxcgi.a

SUBDIRS := xcgid xcgi child

# Now, instantiating the templates for each d.
$(foreach d,$(SUBDIRS),$(eval include $(d)/build.mk))
$(foreach d,$(SUBDIRS),$(eval $(call RULES_template,$(d))))
$(foreach d,$(SUBDIRS),$(eval $(foreach binary,$($(d)_PROGRAM),$(call PROG_template,$(binary),$(d)))))
$(foreach d,$(SUBDIRS),$(eval $(foreach library,$($(d)_ARCHIVE),$(call ARCHIVE_template,$(library),$(d)))))

-include $(sort $(DEPENDENCIES))

clean:
	$(RM) $(foreach d,$(SUBDIRS),$(build_dir)/$(d)/*.o)

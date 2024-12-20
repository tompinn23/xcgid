define RULES_template
$(build_dir)/$(1)/%.o: $(1)/%.c
	@mkdir -p $(build_dir)/$(1)
	$$(CC) $$(CFLAGS) -MMD $$(CFLAGS_$(1)) -I$(1)/include $(foreach library, $($(1)_libs), -I$(basename $(library))/include) -c $$< -o $$@
endef

define PROG_template
DEPENDENCIES := $(DEPENDENCIES) $(patsubst %,$(build_dir)/$(2)/%.d,$(basename $($(1)_sources)))

bin/$(1): $(patsubst %,$(build_dir)/$(2)/%.o,$(basename $($(1)_sources))) $(foreach library, $($(1)_libs), bin/lib$(library))
	@mkdir -p bin/
	$$(CC) $$(LDFLAGS) $$(LDFLAGS_$(2)) $$^ -o $$@

endef

define ARCHIVE_template
DEPENDENCIES := $(DEPENDENCIES) $(patsubst %,$(build_dir)/$(2)/%.d, $(basename $($(1)_sources)))
.PHONY: $(1)
$(1): bin/$(1)
bin/$(1): $(patsubst %,$(build_dir)/$(2)/%.o,$(basename $($(1)_sources)))
	@mkdir -p bin/
	$$(AR) $$(ARFLAGS) $$@ $$?
endef

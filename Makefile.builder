ifeq ($(PACKAGE_SET),dom0)
  RPM_SPEC_FILES := rpm_spec/yubikey-dom0.spec 
else ifeq ($(PACKAGE_SET),vm)
  RPM_SPEC_FILES := rpm_spec/yubikey-vm.spec
endif

# vim: filetype=make

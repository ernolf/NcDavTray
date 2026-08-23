# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: MIT
#
# ncmake bootstrap - fetches and includes the shared Nextcloud app Makefile.
# https://github.com/ernolf/ncmake
#
# Commit this file as the Makefile of your app; it never needs to change again.
# The real Makefile is cached once per machine under ~/.cache/ncmake/ (shared by
# all apps) and keeps itself up to date. Pin a fixed version by setting NCMAKE_REF
# to a tag instead of main.
NCMAKE_REF ?= main
NCMAKE_DIR ?= $(if $(XDG_CACHE_HOME),$(XDG_CACHE_HOME),$(HOME)/.cache)/ncmake
NCMAKE     ?= $(NCMAKE_DIR)/Makefile-$(NCMAKE_REF)
$(if $(wildcard $(NCMAKE)),,$(shell mkdir -p "$(NCMAKE_DIR)" && curl -fsSL "https://raw.githubusercontent.com/ernolf/ncmake/$(NCMAKE_REF)/core/Makefile" -o "$(NCMAKE)"))
ifeq ($(wildcard $(NCMAKE)),)
$(error ncmake: could not fetch the shared Makefile (check your network), see https://github.com/ernolf/ncmake)
endif
include $(NCMAKE)

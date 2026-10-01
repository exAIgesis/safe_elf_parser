#!/bin/bash
alr gnatprove -P safe_elf_parser.gpr --no-subprojects --level=2 --mode="gold" --checks-as-errors=on -U src/*  

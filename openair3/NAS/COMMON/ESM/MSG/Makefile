
ifndef PROJDIR
PROJDIR = $(PWD)/../../..
endif

include $(PROJDIR)/Makerules
include $(PROJDIR)/Makefile.inc

INCLUDES = -I. -I$(INCDIR) -I$(UTILDIR) -I$(IESDIR)

TARGET = $(LIBESMMSG)
TARGETS = $(TARGET).a $(TARGET).so

all: $(TARGETS)

%.o: %.c %.h Makefile $(LIBDIR)/$(LIBIES).a $(UTILDIR)/TLVEncoder.h $(UTILDIR)/TLVDecoder.h
	@echo Compiling $<
	@$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).a: $(OBJS)
	@$(RM) $@
	@$(AR) $(ARFLAGS) $@ $(OBJS)
	@echo Replacing $@ to $(LIBDIR)
	@$(RM) $(LIBDIR)/$@
	@$(CP) $@ $(LIBDIR)

$(TARGET).so: $(OBJS)
	@$(LD) -G -o $@ $(OBJS)
	@echo Replacing $@ to $(LIBDIR)
	@$(RM) $(LIBDIR)/$@
	@$(CP) $@ $(LIBDIR)

clean:
	$(RM) $(OBJS) *.bak *~

veryclean: clean
	$(RM) $(TARGETS)

depend:
	makedepend -- ${CFLAGS} -- ${SRCS}

# DO NOT DELETE THIS LINE -- make depend depends on it.

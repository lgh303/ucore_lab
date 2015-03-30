# OS Lab1 实验报告

2012011303
李国豪 

### 练习1
---
1.	<b> 操作系统镜像文件ucore.img是如何一步一步生成的？（需要比较详细地解释Makefile中每一条相关命令和命令参数的含义，以及说明命令导致的结果） </b>

	>
	```
	bin/ucore.img
	| 生成ucore.img的相关代码为
	| $(UCOREIMG): $(kernel) $(bootblock)
	|	$(V)dd if=/dev/zero of=$@ count=10000
	|	$(V)dd if=$(bootblock) of=$@ conv=notrunc
	|	$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc
	|
	| 为了生成ucore.img，首先需要生成bootblock、kernel
	|
	|>	bin/bootblock
	|	| 生成bootblock的相关代码为
	|	| $(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
	|	|	@echo + ld $@
	|	|	$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ \
	|	|		-o $(call toobj,bootblock)
	|	|	@$(OBJDUMP) -S $(call objfile,bootblock) > \
	|	|		$(call asmfile,bootblock)
	|	|	@$(OBJCOPY) -S -O binary $(call objfile,bootblock) \
	|	|		$(call outfile,bootblock)
	|	|	@$(call totarget,sign) $(call outfile,bootblock) $(bootblock)
	|	|
	|	| 为了生成bootblock，首先需要生成bootasm.o、bootmain.o、sign
	|	|
	|	|>	obj/boot/bootasm.o, obj/boot/bootmain.o
	|	|	| 生成bootasm.o,bootmain.o的相关makefile代码为
	|	|	| bootfiles = $(call listf_cc,boot) 
	|	|	| $(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),\
	|	|	|	$(CFLAGS) -Os -nostdinc))
	|	|	| 实际代码由宏批量生成
	|	|	| 
	|	|	| 生成bootasm.o需要bootasm.S
	|	|	| 实际命令为
	|	|	| gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs \
	|	|	| 	-nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc \
	|	|	| 	-c boot/bootasm.S -o obj/boot/bootasm.o
	|	|	| 其中关键的参数为
	|	|	| 	-ggdb  生成可供gdb使用的调试信息。这样才能用qemu+gdb来调试bootloader or ucore。
	|	|	|	-m32  生成适用于32位环境的代码。我们用的模拟硬件是32bit的80386，所以ucore也要是32位的软件。
	|	|	| 	-gstabs  生成stabs格式的调试信息。这样要ucore的monitor可以显示出便于开发者阅读的函数调用栈信息
	|	|	| 	-nostdinc  不使用标准库。标准库是给应用程序用的，我们是编译ucore内核，OS内核是提供服务的，所以所有的服务要自给自足。
	|	|	|	-fno-stack-protector  不生成用于检测缓冲区溢出的代码。这是for 应用程序的，我们是编译内核，ucore内核好像还用不到此功能。
	|	|	| 	-Os  为减小代码大小而进行优化。根据硬件spec，主引导扇区只有512字节，我们写的简单bootloader的最终大小不能大于510字节。
	|	|	| 	-I<dir>  添加搜索头文件的路径
	|	|	| 
	|	|	| 生成bootmain.o需要bootmain.c
	|	|	| 实际命令为
	|	|	| gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc \
	|	|	| 	-fno-stack-protector -Ilibs/ -Os -nostdinc \
	|	|	| 	-c boot/bootmain.c -o obj/boot/bootmain.o
	|	|	| 新出现的关键参数有
	|	|	| 	-fno-builtin  除非用__builtin_前缀，
	|	|	|	              否则不进行builtin函数的优化
	|	|
	|	|>	bin/sign
	|	|	| 生成sign工具的makefile代码为
	|	|	| $(call add_files_host,tools/sign.c,sign,sign)
	|	|	| $(call create_target_host,sign,sign)
	|	|	| 
	|	|	| 实际命令为
	|	|	| gcc -Itools/ -g -Wall -O2 -c tools/sign.c \
	|	|	| 	-o obj/sign/tools/sign.o
	|	|	| gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
	|	|
	|	| 首先生成bootblock.o
	|	| ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 \
	|	|	obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
	|	| 其中关键的参数为
	|	|	-m <emulation>  模拟为i386上的连接器
	|	|	-nostdlib  不使用标准库
	|	|	-N  设置代码段和数据段均可读写
	|	|	-e <entry>  指定入口
	|	|	-Ttext  制定代码段开始位置
	|	|
	|	| 拷贝二进制代码bootblock.o到bootblock.out
	|	| objcopy -S -O binary obj/bootblock.o obj/bootblock.out
	|	| 其中关键的参数为
	|	|	-S  移除所有符号和重定位信息
	|	|	-O <bfdname>  指定输出格式
	|	|
	|	| 使用sign工具处理bootblock.out，生成bootblock
	|	| bin/sign obj/bootblock.out bin/bootblock
	|
	|>	bin/kernel
	|	| 生成kernel的相关代码为
	|	| $(kernel): tools/kernel.ld
	|	| $(kernel): $(KOBJS)
	|	| 	@echo + ld $@
	|	| 	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	|	| 	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	|	| 	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; \
	|	| 		/^$$/d' > $(call symfile,kernel)
	|	| 
	|	| 为了生成kernel，首先需要 kernel.ld init.o readline.o stdio.o kdebug.o
	|	|	kmonitor.o panic.o clock.o console.o intr.o picirq.o trap.o
	|	|	trapentry.o vectors.o pmm.o  printfmt.o string.o
	|	| kernel.ld已存在
	|	|
	|	|>	obj/kern/*/*.o 
	|	|	| 生成这些.o文件的相关makefile代码为
	|	|	| $(call add_files_cc,$(call listf_cc,$(KSRCDIR)),kernel,\
	|	|	|	$(KCFLAGS))
	|	|	| 这些.o生成方式和参数均类似，仅举init.o为例，其余不赘述
	|	|>	obj/kern/init/init.o
	|	|	| 编译需要init.c
	|	|	| 实际命令为
	|	|	|	gcc -Ikern/init/ -fno-builtin -Wall -ggdb -m32 \
	|	|	|		-gstabs -nostdinc  -fno-stack-protector \
	|	|	|		-Ilibs/ -Ikern/debug/ -Ikern/driver/ \
	|	|	|		-Ikern/trap/ -Ikern/mm/ -c kern/init/init.c \
	|	|	|		-o obj/kern/init/init.o
	|	| 
	|	| 生成kernel时，makefile的几条指令中有@前缀的都不必需
	|	| 必需的命令只有
	|	| ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel \
	|	| 	obj/kern/init/init.o obj/kern/libs/readline.o \
	|	| 	obj/kern/libs/stdio.o obj/kern/debug/kdebug.o \
	|	| 	obj/kern/debug/kmonitor.o obj/kern/debug/panic.o \
	|	| 	obj/kern/driver/clock.o obj/kern/driver/console.o \
	|	| 	obj/kern/driver/intr.o obj/kern/driver/picirq.o \
	|	| 	obj/kern/trap/trap.o obj/kern/trap/trapentry.o \
	|	| 	obj/kern/trap/vectors.o obj/kern/mm/pmm.o \
	|	| 	obj/libs/printfmt.o obj/libs/string.o
	|	| 其中新出现的关键参数为
	|	|	-T <scriptfile>  让连接器使用指定的脚本
	|
	| 生成一个有10000个块的文件，每个块默认512字节，用0填充
	| dd if=/dev/zero of=bin/ucore.img count=10000
	|
	| 把bootblock中的内容写到第一个块
	| dd if=bin/bootblock of=bin/ucore.img conv=notrunc
	|
	| 从第二个块开始写kernel中的内容
	| dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
	```
	

2.	<b> 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？ </b>

	sign.c 的第31行
    buf[510] = 0x55;
    buf[511] = 0xAA;
	总大小为512字节，第510字节为0x55，第511字节为0xAA

### 练习2
---
1.	<b> 从CPU加电后执行的第一条指令开始，单步跟踪BIOS的执行。 </b>

	> * 在makefile中添加内容
	```
	lab1-ex2-1-mon: $(UCOREIMG)
		$(V)$(TERMINAL) -e "$(QEMU) -S -s -d in_asm -D $(BINDIR)/q.log -monitor stdio -hda $< -serial null"
		$(V)sleep 2
		$(V)$(TERMINAL) -e "gdb -q -x tools/lab1-ex2-1-init"
	```
	> * 对以上命令的一些解释
	```
	$(V)$(TERMINAL) -e ".." --> @gnome-terminal -e ".."
	启动一个terminal 且取消会显，在其中执行qemu命令
	qemu-system-i386 -S -s -d in_asm -D q.log -monitor stdio -hda ucore.img -serial null
    -S : 虚拟机启动后立即暂停,等侍gdb连接
	-s : 在1234接受gdb调试连接
	-d : 一些调试信息的参数
	-D : 指定调试信息输出文件
	-hda : 后面指定 disk 0
	Makefile 中的 $< 是第一个依赖对象
	```
	> * 新建tools/lab1-ex2-1-init，在里面添加内容
	```
	file bin/kernel
	target remote :1234
	set architecture i8086
	```
	> * 在终端使用命令
	```
	make lab1-ex2-1-mon
	```
	进入调试模式
	> * 使用si命令进行单步调试
	
2.	<b> 在初始化位置0x7c00设置实地址断点,测试断点正常。 </b>

	> * 在makefile中添加内容
	```
	lab1-ex2-2-mon: $(UCOREIMG)
		$(V)$(TERMINAL) -e "$(QEMU) -S -s -d in_asm -D $(BINDIR)/q.log -monitor stdio -hda $< -serial null"
		$(V)sleep 2
		$(V)$(TERMINAL) -e "gdb -q -x tools/lab1-ex2-2-init"
	```
	> * 新建tools/lab1-ex2-2-init，在里面添加内容
	```
	file bin/kernel
	target remote :1234
	set architecture i8086
	b *0x7c00
	continue
	```
	> * 在终端使用命令进入调试模式
	```
	make lab1-ex2-2-mon
	```
	
3.	<b> 从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与bootasm.S和 bootblock.asm进行比较。 </b>
	
	> * 在终端使用命令进入调试模式
	```
	make lab1-ex2-2-mon
	```
	> * 输入continue运行
	> * 在bin/q.log中查看刚才运行的结果
	```
	0x000fd12d:  cli    
	0x000fd12e:  cld    
	0x000fd12f:  mov    $0x8f,%eax
	0x000fd135:  out    %al,$0x70
	0x000fd137:  in     $0x71,%al
	0x000fd139:  in     $0x92,%al
	0x000fd13b:  or     $0x2,%al
	0x000fd13d:  out    %al,$0x92
	0x000fd13f:  lidtw  %cs:0x66c0
	0x000fd145:  lgdtw  %cs:0x6680
	0x000fd14b:  mov    %cr0,%eax
	0x000fd14e:  or     $0x1,%eax
	0x000fd152:  mov    %eax,%cr0
	----------------
	IN: 
	0x000fd155:  ljmpl  $0x8,$0xfd15d
	----------------
	IN: 
	0x000fd15d:  mov    $0x10,%eax
	0x000fd162:  mov    %eax,%ds
	----------------
	IN: 
	0x000fd164:  mov    %eax,%es
	----------------
	IN: 
	0x000fd166:  mov    %eax,%ss
	----------------
	IN: 
	0x000fd168:  mov    %eax,%fs
	----------------
	IN: 
	0x000fd16a:  mov    %eax,%gs
	0x000fd16c:  mov    %ecx,%eax
	0x000fd16e:  jmp    *%edx
	```
	> * 和bootasm.S与bootblock.asm比对，发现代码一致

4.	<b> 自己找一个bootloader或内核中的代码位置，设置断点并进行测试。 </b>

	> * 在makefile中添加内容
	```
	lab1-ex2-4-mon: $(UCOREIMG)
		$(V)$(TERMINAL) -e "$(QEMU) -S -s -d in_asm -D $(BINDIR)/q.log -monitor stdio -hda $< -serial null"
		$(V)sleep 2
		$(V)$(TERMINAL) -e "gdb -q -x tools/lab1-ex2-4-init"
	```
	> * 新建tools/lab1-ex2-4-init，在里面添加内容
	```
	file obj/bootblock.o
	target remote :1234
	b bootmain.c:89
	continue
	```
	> * 在终端使用命令进入调试模式，成功跳到断点bootmain.c中的第92行
	```
	make lab1-ex2-4-mon
	```

### 练习3
---
1.	<b> 请分析bootloader是如何完成从实模式进入保护模式的。 </b>

	> * 将flag和段寄存器ds、es、ss置0
	```
	.code16
		cli
		cld
		xorw %ax, %ax
		movw %ax, %ds
		movw %ax, %es
		movw %ax, %ss
	```
	> * 等待8042键盘控制器不忙，将数据0xd1送到端口0x64，将数据0xdf送到端口0x60，开启A20
	```
	seta20.1:
		inb $0x64, %al
		testb $0x2, %al
		jnz seta20.1
		movb $0xd1, %al
		outb %al, $0x64
	seta20.2:
		inb $0x64, %al
		testb $0x2, %al
		jnz seta20.2
		movb $0xdf, %al
		outb %al, $0x60
	```
	> * 加载GDT，使能cr0寄存器的PE位，从实模式进入保护模式
	```
		lgdt gdtdesc
		movl %cr0, %eax
		orl $CR0_PE_ON, %eax
		movl %eax, %cr0
	```
	> * 跳转到32位地址下的下一条指令
	```
		ljmp $PROT_MODE_CSEG, $protcseg
	```
	> * 设置保护模式下的段寄存器DS、ES、FS、GS、SS
	```
	.code32
	protcseg:
		movw $PROT_MODE_DSEG, %ax
		movw %ax, %ds
		movw %ax, %es
		movw %ax, %fs
		movw %ax, %gs
		movw %ax, %ss
	```
	> * 建立栈指针EBP、ESP，表示栈空间为0~start，跳转到bootmain函数
	```
		movl $0x0, %ebp
		movl $start, %esp
		call bootmain
	```

### 练习4
---
1.	<b> bootloader如何读取硬盘扇区的？ </b>

	> * 观察readsect函数
	> * 等待硬盘，准备输出读入配置信息
	```
	waitdisk();
	```
	> * 将读取数量设为1，写入地址0x1F2
	```
	outb(0x1F2, 1);
	```
	> * 将32位的磁盘号secno分成四段，每段8位，依次写入0x1F6~0x1F3，其中最高的4位强制设为1110
	```
	outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
	```
	> * 将命令0x20写入地址0x1F7，表示读取扇区
	```
	outb(0x1F7, 0x20);
	```
	> * 等待磁盘，准备读入数据
	```
	waitdisk();
	```
	> * 从地址0x1F0读入数据到指针dst处
	```
	insl(0x1F0, dst, SECTSIZE / 4);
	```

2.	<b> bootloader是如何加载ELF格式的OS？ </b>

	> * 观察bootmain函数
	> * 从硬盘读入ELF文件头，大小为8个扇区
	```
	readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);
	```
	readseg函数使用readsect函数循环从硬盘读取扇区
	> * ELF文件头的格式如下
	```
	struct elfhdr {
		uint32_t e_magic;     // must equal ELF_MAGIC
		uint8_t e_elf[12];
		uint16_t e_type;      // 1=relocatable, 2=executable, 3=shared object, 4=core image
		uint16_t e_machine;   // 3=x86, 4=68K, etc.
		uint32_t e_version;   // file version, always 1
		uint32_t e_entry;     // entry point if executable
		uint32_t e_phoff;     // file position of program header or 0
		uint32_t e_shoff;     // file position of section header or 0
		uint32_t e_flags;     // architecture-specific flags, usually 0
		uint16_t e_ehsize;    // size of this elf header
		uint16_t e_phentsize; // size of an entry in program header
		uint16_t e_phnum;     // number of entries in program header or 0
		uint16_t e_shentsize; // size of an entry in section header
		uint16_t e_shnum;     // number of entries in section header or 0
		uint16_t e_shstrndx;  // section number that contains section name strings
	};
	```
	> * 取出ELF文件头中的e_magic成员是否符合要求
	```
	if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }
	```
	> * 用ELF文件头中的程序头信息：e_phoff和e_phnum，来创建程序头
	```
	struct proghdr *ph, *eph;
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
	```
	> * 同样使用readseg来读取程序头
	```
	for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }
	```
	> * 调用ELF文件头的入口函数，进入下一步加载
	```
	((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
	```

### 练习5
---
1.	<b> 在lab1中完成kdebug.c中函数print_stackframe的实现，可以通过函数print_stackframe来跟踪函数调用堆栈中记录的返回地址。 </b>

	> * 根据print_stackframe函数中的提示完成函数
	> * (1) call read_ebp() to get the value of ebp. the type is (uint32_t); <br/> (2) call read_eip() to get the value of eip. the type is (uint32_t);
	```
	uint32_t ebp = read_ebp();
	uint32_t eip = read_eip();
	```
	> * (3) from 0 .. STACKFRAME_DEPTH
	```
	for (i = 0; i < STACKFRAME_DEPTH; ++i)
	```
 	> * (3.1) printf value of ebp, eip
	```
	cprintf("ebp:0x%08x eip:0x%08x args:", ebp, eip);
	```
	> * (3.2) (uint32_t)calling arguments [0..4] = the contents in address (unit32_t)ebp +2 [0..4] <br/> (3.3) cprintf("\n");
	```
	for (j = 0; j < 4; ++j) {
		cprintf("0x%08x ", ((uint32_t *)ebp + 2)[j]);
			}
	cprintf("\n");
	```
	> * (3.4) call print_debuginfo(eip-1) to print the C calling function name and line number, etc.
	```
	print_debuginfo(eip - 1);
	```
	> * (3.5) popup a calling stackframe <br/> NOTICE: the calling funciton's return addr eip  = ss:[ebp+4] <br/> the calling funciton's ebp = ss:[ebp]
	```
	eip = *((uint32_t *)ebp + 1);
	ebp = *((uint32_t *)ebp + 0);
	```
	> * 观察输出，发现后面多输出了很多类似
	```
	ebp:0x00000000 eip:0x00000000 args:0xf000e2c3 0xf000ff53 0xf000ff53 0xf000ff53 
    <unknow>: -- 0xffffffff --
	```
	的东西，应该只输出一个。这时就需要在循环的时候判断ebp的值来及时停止循环
	> * 完整的代码如下
	```
void
print_stackframe(void) {
	 uint32_t ebp = read_ebp();
	 uint32_t eip = read_eip();
	 int i;
	 for (i = 0; i < STACKFRAME_DEPTH && ebp != 0; ++i)
	 {
		  cprintf("ebp:0x%08x eip:0x%08x args:", ebp, eip);
		  int j;
		  for (j = 0; j < 4; ++j)
			   cprintf("0x%08x ", ((uint32_t *)ebp + 2)[j]);
		  cprintf("\n");
		  print_debuginfo(eip - 1);
		  eip = *((uint32_t *)ebp + 1);
		  ebp = *((uint32_t *)ebp + 0);
	 }
}
	```

### 练习6
---
1.	<b> 中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？ </b>

	> * 查看mmu.h中的结构gatedesc，其用了16+16+5+3+4+1+2+1+16=64位，即占8字节
	> * 中断描述符gatedesc中，0~15位表示段偏移量低16位，16~31位表示段描述符，48~63位表示段偏移量高16位，这些数据共同描述了中断处理代码的入口

2.	<b> 编程完善kern/trap/trap.c中对中断向量表进行初始化的函数idt_init。在idt_init函数中，依次对所有中断入口进行初始化。使用mmu.h中的SETGATE宏，填充idt数组内容。每个中断的入口由tools/vectors.c生成，使用trap.c中声明的vectors数组即可。 </b>

	> * 根据trap.c中的idt_init函数提示完成函数
	> * (1) Where are the entry addrs of each Interrupt Service Routine (ISR)? All ISR's entry addrs are stored in __vectors. where is uintptr_t __vectors[] ?  __vectors[] is in kern/trap/vector.S which is produced by tools/vector.c (try "make" command in lab1, then you will find vector.S in kern/trap DIR) You can use  "extern uintptr_t __vectors[];" to define this extern variable which will be used later.
	```
	extern uintptr_t __vectors[];
	```
	> * (2) Now you should setup the entries of ISR in Interrupt Description Table (IDT). Can you see idt[256] in this file? Yes, it's IDT! you can use SETGATE macro to setup each item of IDT <br/>
先忽略了T_SYSCALL<br/>
	```
	for (i = 0; i < 256; ++i) {
			SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
		}
	}
	```
	> * After setup the contents of IDT, you will let CPU know where is the IDT by using 'lidt' instruction. <br/> You don't know the meaning of this instruction? just google it! and check the libs/x86.h to know more. <br/> Notice: the argument of lidt is idt_pd. try to find it!
	```
	lidt(&idt_pd);
	```
	> * 完整代码
	```
    extern uintptr_t __vectors[];
    int i;
    for (i = 0; i < sizeof(idt) / sizeof(struct gatedesc); i ++) {
        SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
    }
    lidt(&idt_pd);
	```

3.	<b> 编程完善trap.c中的中断处理函数trap，在对时钟中断进行处理的部分填写trap函数中处理时钟中断的部分，使操作系统每遇到100次时钟中断后，调用print_ticks子程序，向屏幕上打印一行文字”100 ticks”。 </b>
	> * 根据trap_dispatch函数中的提示完成函数
	> * (1) After a timer interrupt, you should record this event using a global variable (increase it), such as ticks in kern/driver/clock.c <br/> (2) Every TICK_NUM cycle, you can print some info using a funciton, such as print_ticks(). <br/> (3) Too Simple? Yes, I think so! <br/> 申请一个全局变量TICK_COUNT，每计100次调用print_ticks函数即可。
	```
	TICK_COUNT++;
	if (TICK_COUNT == TICK_NUM) {
		print_ticks();
		TICK_COUNT = 0;
	}
	```
## 6.5 添加新系统调用

&emsp;&emsp;系统调用是用户空间和内核空间交互的一种有效手段。除了系统本身提供的系统调用外，我们也可以添加自己的系统调用。

&emsp;&emsp;实现一个新的系统调用的第一步是决定它的用途。它要做些什么？每个系统调用都应该有一个明确的用途。在Linux中不提倡采用多用途的（一个系统调用通过传递不同的参数值来选择完成不同的工作）系统调用。

&emsp;&emsp;新系统调用的参数、返回值和错误码又该是什么呢？系统调用的界面应该力求简洁，参数尽可能少。系统调用的语义和行为非常关键；因为应用程序依赖它们，所以它们应力求稳定，不作改动。

&emsp;&emsp;设计接口的时候要尽量为将来多做考虑。你是不是对函数做了不必要的限制？系统调用被设计的越通用越好。不要假设这个系统调用现在怎么用将来也一定就是这么用。系统调用的目的可能不变，但它的用法却可能改变。这个系统调用可移植吗？要确保不对系统调用做错误的假设，否则将来这个调用就可能会崩溃。记住Unix的格言：“提供机制而不是策略”。

&emsp;&emsp;当你写一个系统调用的时候，要时刻注意可移植性和健壮性，不但要考虑当前，还要为将来做打算。基本的Unix系统调用经受住了时间的考验；它们中的很大一部分到现在都还和30年前一样适用和有效。

&emsp;&emsp;首先我们通过添加一个简单的系统调用说明其实现步骤，然后说明如何添加一个稍微复杂的系统调用。

&emsp;&emsp;系统调用的实现需要调用内核中的函数，对于不同架构，添加系统调用的步骤截然不同，这里使用x86架构作演示。另外，内核版本不同，其内核函数名可能稍有差异，假定我们使用的内核版本为3.10.0。内核源代码的目录根据发行版不同，位置不同。ubuntu的内核源码通常为/usr/src/，centos则需要自行下载。

### 6.5.1 添加系统调用的步骤

&emsp;&emsp;我们要添加的这个系统调用没有返回值，也不用传递参数，其名取为mysyscall。其功能是使用户的uid等于0。步骤如下：

#### 1．在系统调用表中添加相应表项

&emsp;&emsp;如前所述，系统调用处理程序system_call会根据eax中的号到系统调用表sys_call_table中查找相应的系统调用服务例程，因此，我们必须把自己的服务例程sys_mysyscall添加到系统调用表中。x86架构的系统调用号添加也在这个表里。系统调用表位于汇编语言arch/x86/syscalls/syscall_32.tbl中：
```c
# The format is:
# <number> <abi> <name> <entry point> <compat entry point>
#
# The abi is always "i386" for this file.
#
0	i386	restart_syscall		sys_restart_syscall
1	i386	exit			sys_exit
2	i386	fork			sys_fork			stub32_fork
3	i386	read			sys_read
...
356	i386	memfd_create		sys_memfd_create
374	i386	userfaultfd		sys_userfaultfd
375	i386	mysyscall		sys_mysyscall
```
可以看到，我们在文件末尾添加了375号系统调用mysyscall。

#### 2．添加函数声明

我们需要在include/linux/syscalls.h文件里将系统调用处理函数进行声明。
```c
asmlinkage int sys_mysyscall(void);
```
&emsp;&emsp;其中的asmlinkage修饰符是gcc中一个比较特殊的标志。因为gcc常用的一种编译优化方法是使用寄存器传递函数的参数，而加了asmlinkage修饰符的函数必须从堆栈中而不是寄存器中获取参数。内核中所有系统调用的实现都使用了这个修饰符。
&emsp;&emsp;到此为止，内核已经能够正确地找到并且调用sys_mysyscall。接下来，就要实现该例程。

#### 3．实现系统调用服务例程

&emsp;&emsp;我们把sys_mysyscall添加在kernel目录下的系统调用文件sys.c中：

```c
SYSCALL_DEFINE0(mysyscall)
{
		return current->cred->uid.val;
}
```
如前所述，SYSCALL_DEFINE0用于生成没有参数的系统调用服务例程。

#### 4．重新编译内核

&emsp;&emsp;通过以上三个步骤，我们要添加一个新系统调用的所有工作已经完成。但是，要使这个系统调用真正在内核运行起来，我还需要对内核进行重新编译。关于内核的编译，请参阅相关资料。

#### 5．编写用户态程序

&emsp;&emsp;要测试新添加的系统调用，我们可以编写一个用户程序来调用这个系统调用：

```c
#include<stdio.h>
#define __NR_mysyscall 375
int main()
{
	printf(“This is my uid:%d.\n”, getuid());
	int uid = syscall(__NR_mysyscall);
	printf(“My uid is:%d.\n”, uid);
}
```

&emsp;&emsp;上面这个例子是把系统调用直接加入内核，因此，需要重新编译内核。下面的例子是把系统调用以模块的形式加载到内核。

### 6.5.2 系统调用的调试

&emsp;&emsp;添加新的系统调用主要是对内核进行修改并编译。如果在用户态无法成功调用所加系统调用，此时，需判断是系统调用没有加进内核还是用户态的测试程序出现问题。下面给出一种解决方法，也就是将源码中的一部分提出来在用户态进行检测，如果没有添加成功，可以根据返回的错误码进行识别并处理。检测程序如下：

```c
#include<stdio.h>
#include<unistd.h>
int main()
{
	unsigned long sys_num=375;/*这里的数值是新添加的系统调用的系统调用号*/
	unsigned long value=0;
	__asm__ ("int $0x80":"=a"(value):"0"((long)(sys_num)));
	printf ("The value is %ld\n", value);
	return value;
}
```

&emsp;&emsp;通过返回值来查看问题所在，如果返回－38则说明没有添加成功，返回－1则说明没有操作的许可权。更多可以查看/include/uapi/asm-generic/errno.h

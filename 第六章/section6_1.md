## 6.1 系统调用与应用编程接口、系统命令以及内核函数之关系

&emsp;&emsp;程序员或系统管理员并非直接与系统调用打交道，在实际使用中程序员调用的是应用编程接口API(Application Programming Interface)，而管理员使用的则是系统命令。

### 6.1.1 系统调用与API

&emsp;&emsp;Linux的应用编程接口（API）遵循了在Unix世界中最流行的应用编程接口标准——POSIX标准。POSIX标准是针对API而不是针对系统调用的。判断一个系统是否与POSIX兼容要看它是否提供了一组合适的应用编程接口，而不管对应的函数是如何实现的。事实上，一些非Unix系统被认为是与POSIX兼容的，是因为它们在用户态的库函数中提供了传统Unix能提供的所有服务。

&emsp;&emsp;应用编程接口(API)其实是一个函数定义，比如常见的read()、malloc()、free（）、abs()函数等，这些函数说明了如何获得一个给定的服务；而系统调用是通过软中断向内核发出一个明确的请求。

&emsp;&emsp;API有可能和系统调用的调用形式一致，比如read()函数就和read()系统调用的调用形式一致。但是，情况并不总是这样，这表现在两个方面，一种是几个不同的API其内部实现可能调用了同一个系统调用，例如，Linux的libc库实现了内存分配和释放的函数malloc(
)、calloc( )和free( )，这几个函数的实现都调用了brk(
)系统调用；另一方面,一个API的实现调用了好几个系统调用。更有些API甚至不需要任何系统调用，因为它们不需要内核提供的服务。

&emsp;&emsp;从编程者的观点看，API和系统调用之间没有什么差别,二者关注的都是函数名、参数类型及返回代码的含义。然而，从设计者的观点看，这是有差别的，因为系统调用实现是在内核完成的，而用户态的函数是在函数库中实现的。

### 6.1.2 系统调用与系统命令 

&emsp;&emsp;系统命令相对应用编程接口更高一层，每个系统命令都是一个可执行程序，比如常用的系统命令ls、hostname等，这些命令的实现调用了系统调用。Linux的系统命令多数位于/bin和/sbin目录下。如果通过strace命令查看它们所调用的系统调用，比如
strace ls或strace hostname，就会发现它们调用了诸如open、brk、fstat、ioctl
等系统调用。

### 6.1.3 系统调用与内核函数

&emsp;&emsp;内核函数与普通函数形式上没有什么区别，只不过前者在内核实现，因此要满足一些内核编程的要求[^1]。系统调用是用户进程进入内核的接口层，它本身并非内核函数，但它是由内核函数实现的，进入内核后，不同的系统调用会找到各自对应的内核函数，这些内核函数被称为系统调用的**“服务例程”**。比如系统调用
getpid实际调用的服务例程为sys_getpid()，或者说系统调用getpid()是服务例程sys_getpid()的“**封装例程”**。
&emsp;&emsp;但是内核代码里没有名为sys_getpid()的函数，而是由SYSCALL_DEFINE0宏定义的，下面是sys_getpid()在内核的具体实现，代码位置kernel/sys.c：

[^1]: 内核编程相比用户编程有一些特点，简单地讲内核程序一般不能引用C库函数；缺少内存保护措施；堆栈有限（因此调用嵌套不能过多）；而且由于调度关系，必须考虑内核执行路径的连续性，不能有长睡眠等行为。

```c
SYSCALL_DEFINE0(getpid)
{
	return task_tgid_vnr(current);
}
```
&emsp;&emsp;SYSCALL_DEFINE0宏的作用是生成没有参数的系统调用函数，我们将在6.4章节说明SYSCALL_DEFINEx系列宏的作用。
SYSCALL_DEFINE0实现如下，代码位置include/linux/syscalls.h：
```c
#define SYSCALL_DEFINE0(sname)					\
	SYSCALL_METADATA(_##sname, 0);				\
	asmlinkage long sys_##sname(void)
```
&emsp;&emsp;如果想直接调用服务例程，Linux提供了一个syscall()函数，下面我们举例来对比一下调用系统调用和直接调用内核函数的区别。

```c
#include<syscall.h>
#include<unistd.h>
#include<stdio.h>
#include<sys/types.h>
int main(void)
{
		long ID1, ID2;
		/*-----------------------------*/
		/* 直接调用内核函数*/
		/*-----------------------------*/
		ID1 = syscall(SYS_getpid);
		printf ("syscall(SYS_getpid)=%ld\n", ID1);
		/*-----------------------------*/
		/* 调用系统调用 */
		/*-----------------------------*/
		ID2 = getpid();
		printf ("getpid()=%ld\n", ID2);
		return(0);
}
```

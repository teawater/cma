#include <iostream>
using namespace std;

class	test {
	//friend	class test2;
	public:
		test();
		void	b();
	private:
		int	a;
		char	buf[101];
};


class	test2 {
	public:
		void	cool(test &t1);
		void	cool2();
		void	cool3(test &t1);
		void	cool4();
		int	cool5(char *a);
	private:
		char	*c;
		void	cool6();
};

class test3 {
	public:
		static void	init();
		static test	*a;
		static test2	*b;
};


test::test()
{
	a=1;
	buf[0]='0';
	buf[1]='1';
	buf[2]='2';
	buf[3]='3';
	buf[4]='\0';
}

void
test::b()
{
	test3::b->cool2();
	test3::b->cool(*this);
	cout<<"cool"<<a<<"\n";
	test3::b->cool3(*this);
	test3::b->cool3(*this);
	test3::b->cool3(*this);
	test3::b->cool4();

	cout<<test3::b->cool5(buf)<<"\n";
	cout<<buf<<"\n";
}

test	*test3::a=NULL;
test2	*test3::b=NULL;

void
test3::init()
{
	a=new test;
	b=new test2;
cout<<""<<sizeof(*a)<<"\n";
cout<<""<<sizeof(*b)<<"\n";
}

void
test2::cool(test &t1)
{
//	cout<<"cool"<<t1.a<<"\n";
//	t1.a=3;
}

void
test2::cool2()
{
	cout<<"cool"<<"\n";
}

void
test2::cool3(test &t1)
{
	static int	w=1;

	cout<<"cool"<<w++<<"\n";
}

void
test2::cool4()
{
	int	i;
	char	a[]="01234567890";
	int	b=4473924;
	int	*c;

	c=(int *)(a+1);
	*c=b;
	for(i=0;i<10;i++)
		cout<<a[i];
	cout<<"\n";
}

int
test2::cool5(char *a)
{
	c=a;
	cool6();
	return(3);
}

void
test2::cool6()
{
	cout<<c<<"\n";
	c[0]=108;
}

int
main(int argc,char *argv[],char *envp[])
{
	test3::init();

	test3::a->b();

	delete test3::a;
	//delete test3::b;

	while(1);

	return(0);
}

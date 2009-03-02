#define toupper(x) (((x) >= 'a' && (x) <= 'z') ? ((x) + 'A' - 'a') : (x))

int str_replace_char (char *string, char ch1, char ch2)
{
	int count = 0;

	for (char* sp = string; *sp; sp++)
	{
		if (*sp == ch1)
		{
			*sp = ch2;
			++ count;
		}
	}

	return count;
}

int stri_replace_char (char *string, char ch1, char ch2)
{
	int count = 0;

	ch1 = toupper (ch1);

	for (char* sp = string; *sp; sp++)
	{
		if (toupper(*sp) == ch1)
		{
			*sp = ch2;
			++ count;
		}
	}

	return count;
}

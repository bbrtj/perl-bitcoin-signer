package Signer::Role::ReadsPasswords;

use v5.38;

use Moo::Role;
use Term::ReadKey;

sub read_password ($self)
{
	print 'Please provide a wallet password: ';
	ReadMode 'noecho';
	my $passwd = readline STDIN;
	ReadMode 'restore';
	say ''; # newline

	chomp $passwd;
	return $passwd;
}


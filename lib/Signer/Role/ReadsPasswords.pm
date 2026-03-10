package Signer::Role::ReadsPasswords;

use v5.40;

use Mooish::Base -role;
use Term::ReadKey;

sub read_password ($self, $type)
{
	print "Please provide a $type password: ";
	ReadMode 'noecho';
	my $passwd = readline STDIN;
	ReadMode 'restore';
	say '';    # newline

	chomp $passwd;
	return $passwd;
}


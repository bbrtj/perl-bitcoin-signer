package Signer::Input;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Types::Common qw(Str SimpleStr);

has param 'password' => (
	isa => SimpleStr,
	default => '',
);


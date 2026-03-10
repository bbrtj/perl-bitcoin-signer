package Signer::Input;

use v5.40;
use Mooish::Base;

has param 'password' => (
	isa => SimpleStr,
	default => '',
);


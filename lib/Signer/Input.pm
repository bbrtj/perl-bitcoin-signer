package Signer::Input;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Types::Common qw(InstanceOf HashRef ArrayRef PositiveNum SimpleStr PositiveOrZeroInt);

use Bitcoin::Crypto::Transaction::UTXO;
use Bitcoin::Crypto::Transaction::Output;

has param 'password' => (
	isa => SimpleStr,
);

has param 'change_index' => (
	isa => PositiveOrZeroInt,
	default => 0,
);

has param 'address_search_start' => (
	isa => PositiveOrZeroInt,
	default => 0,
);

# utxos for input
has param 'inputs' => (
	coerce => ArrayRef [(InstanceOf ['Bitcoin::Crypto::Transaction::UTXO'])
		->plus_coercions(
			HashRef, q{
				Bitcoin::Crypto::Transaction::UTXO->new($_);
			},
		)],
);

# outputs
has param 'outputs' => (
	coerce => ArrayRef[(InstanceOf ['Bitcoin::Crypto::Transaction::Output'])
		->plus_coercions(
			HashRef, q{
				Bitcoin::Crypto::Transaction::Output->new($_);
			},
		)],
);

has param 'fee_rate' => (
	isa => PositiveNum->where(q{ $_ > 1 }),
);


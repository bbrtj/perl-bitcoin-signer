package Signer::Input::Transaction;

use v5.40;
use Mooish::Base;

use Bitcoin::Crypto::Transaction::UTXO;
use Bitcoin::Crypto::Transaction::Output;

extends 'Signer::Input';

has param 'change' => (
	isa => SimpleStr,
	required => 0,
);

has param 'change_search_from' => (
	isa => PositiveOrZeroInt,
	default => 0,
);

has param 'change_search_to' => (
	isa => PositiveOrZeroInt,
	default => 20,
);

has param 'address_search_from' => (
	isa => PositiveOrZeroInt,
	default => 0,
);

has param 'address_search_to' => (
	isa => PositiveOrZeroInt,
	default => 20,
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

has param 'self_outputs' => (
	isa => ArrayRef[PositiveOrZeroInt],
	default => sub { [] },
);

has param 'fee_rate' => (
	isa => PositiveNum->where(q{ $_ > 0 }),
);


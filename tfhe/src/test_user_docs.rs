use doc_comment::doctest;

// README
doctest!("../../README.md", readme);

// GETTING STARTED
doctest!(
    "../docs/getting_started/quick_start.md",
    getting_started_quick_start
);
doctest!(
    "../docs/getting_started/operations.md",
    getting_started_operations
);

// HOW TO
doctest!("../docs/how_to/compress.md", how_to_compress);
doctest!("../docs/how_to/public_key.md", how_to_public_key);
doctest!(
    "../docs/how_to/parallelized_pbs.md",
    how_to_parallelized_pbs
);
doctest!("../docs/how_to/serialization.md", how_to_serialize);
doctest!(
    "../docs/how_to/trivial_ciphertext.md",
    how_to_trivial_ciphertext
);

//FINE GRAIN API
//
// fine_grain_api/Boolean
doctest!(
    "../docs/fine_grain_api/Boolean/parameters.md",
    booleans_parameters
);
doctest!(
    "../docs/fine_grain_api/Boolean/operations.md",
    booleans_operations
);
doctest!(
    "../docs/fine_grain_api/Boolean/serialization.md",
    booleans_serialization
);
doctest!(
    "../docs/fine_grain_api/Boolean/tutorial.md",
    booleans_tutorial
);

// fine_grain_api/shortint
doctest!(
    "../docs/fine_grain_api/shortint/parameters.md",
    shortint_parameters
);
doctest!(
    "../docs/fine_grain_api/shortint/serialization.md",
    shortint_serialization
);
doctest!(
    "../docs/fine_grain_api/shortint/tutorial.md",
    shortint_tutorial
);
doctest!(
    "../docs/fine_grain_api/shortint/operations.md",
    shortint_operations
);

// fine_grain_api/integer
doctest!(
    "../docs/fine_grain_api/integer/tutorial.md",
    integer_first_circuit
);
doctest!(
    "../docs/fine_grain_api/integer/operations.md",
    integer_operations
);
doctest!(
    "../docs/fine_grain_api/integer/serialization.md",
    integer_serialization_tuto
);

// core_crypto
doctest!(
    "../docs/core_crypto/presentation.md",
    core_crypto_presentation
);
doctest!("../docs/core_crypto/tutorial.md", core_crypto_tutorial);

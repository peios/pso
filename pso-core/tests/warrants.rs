//! Warrant values and the narrowing rule (§7.5).

use pso_core::{Malformed, Warrant, check_narrowing, name_is_within, valid_leaf_name};

#[test]
fn a_name_is_within_its_own_domain_and_no_lookalike() {
    assert!(name_is_within("example.com", "example.com"));
    assert!(name_is_within("pkgs.example.com", "example.com"));
    assert!(name_is_within("a.b.example.com", "example.com"));
    assert!(name_is_within("anything.example", "."));
    assert!(!name_is_within("evilexample.com", "example.com"));
    assert!(!name_is_within("example.com", "pkgs.example.com"));
    assert!(!name_is_within("example.org", "example.com"));
}

#[test]
fn a_leaf_name_is_lowercase_labels_and_never_the_universal_name() {
    assert!(valid_leaf_name("pkgs.example.com"));
    assert!(valid_leaf_name("xn--bcher-kva.example"));
    assert!(!valid_leaf_name("."));
    assert!(!valid_leaf_name("Example.com"));
    assert!(!valid_leaf_name("example..com"));
    assert!(!valid_leaf_name(".example.com"));
    assert!(!valid_leaf_name(""));
}

#[test]
fn a_set_refuses_empty_and_repeated_elements() {
    assert!(Warrant::set("Class", &[], true).is_ok());
    assert!(Warrant::set("Class", &["a", "b"], true).is_ok());
    assert_eq!(
        Warrant::set("Class", &["a", ""], true),
        Err(Malformed::BadWarrant)
    );
    assert_eq!(
        Warrant::set("Class", &["a", "a"], true),
        Err(Malformed::BadWarrant)
    );
    assert_eq!(
        Warrant::set("Class", &["tab\there"], true),
        Err(Malformed::BadWarrant)
    );
}

#[test]
fn a_namespace_needs_a_name_and_a_warrant_name_has_a_narrow_alphabet() {
    assert_eq!(
        Warrant::namespace("Name", &[], true),
        Err(Malformed::BadWarrant)
    );
    assert_eq!(
        Warrant::namespace("Name", &["Example.com"], true),
        Err(Malformed::BadWarrant)
    );
    assert_eq!(
        Warrant::set("Has Space", &[], true),
        Err(Malformed::BadWarrant)
    );
    assert_eq!(Warrant::set("", &[], true), Err(Malformed::BadWarrant));
}

#[test]
fn a_child_holds_no_more_than_its_parent() {
    let parent = vec![
        Warrant::set("Class", &["a", "b"], true).unwrap(),
        Warrant::limit("Budget", 5, true).unwrap(),
        Warrant::namespace("Name", &["example.com"], true).unwrap(),
    ];
    let narrower = vec![
        Warrant::set("Class", &["b"], true).unwrap(),
        Warrant::limit("Budget", 5, true).unwrap(),
        Warrant::namespace("Name", &["a.example.com", "b.example.com"], true).unwrap(),
    ];
    assert!(check_narrowing(&narrower, &parent).is_ok());
    assert!(
        check_narrowing(&[], &parent).is_ok(),
        "dropping a warrant is narrowing"
    );

    let wider_set = [Warrant::set("Class", &["a", "c"], true).unwrap()];
    assert!(check_narrowing(&wider_set, &parent).is_err());
    let wider_limit = [Warrant::limit("Budget", 6, true).unwrap()];
    assert!(check_narrowing(&wider_limit, &parent).is_err());
    let added = [Warrant::set("Extra", &[], true).unwrap()];
    assert!(check_narrowing(&added, &parent).is_err());
    let other_type = [Warrant::set("Budget", &["5"], true).unwrap()];
    assert!(check_narrowing(&other_type, &parent).is_err());
}

#[test]
fn a_strict_warrant_must_differ_from_its_parent() {
    let parent = [
        Warrant::delegate(3),
        Warrant::set("Once", &["a", "b"], false).unwrap(),
    ];
    assert!(check_narrowing(&[Warrant::delegate(2)], &parent).is_ok());
    assert!(check_narrowing(&[Warrant::delegate(3)], &parent).is_err());
    let same_elements = [Warrant::set("Once", &["b", "a"], false).unwrap()];
    assert!(
        check_narrowing(&same_elements, &parent).is_err(),
        "order does not make a set differ"
    );
    let fewer = [Warrant::set("Once", &["a"], false).unwrap()];
    assert!(check_narrowing(&fewer, &parent).is_ok());
}

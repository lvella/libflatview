use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use crate::Error;

type Key<'a> = Vec<Component<'a>>;

/// Resolves relative paths and existing symbolic links up to the point where
/// paths are accessible.
///
/// This can only fail if the paths are malformed (i.e. `Error::EmptyPath`: one
/// of the paths is empty), never on filesystem errors.
pub fn resolve_known_paths<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<Vec<PathBuf>, Error> {
    let paths = paths
        .into_iter()
        .map(|p| get_path_components(p))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(resolve_known_paths_impl(paths))
}

/// Get the path components with the guarantee that relative paths starts with
/// dots and empty paths returns Error::EmptyPath.
fn get_path_components(path: &Path) -> Result<Key<'_>, Error> {
    let mut comps = Vec::new();

    // Add CurDir if the path is relative but doesn't contain a ".".
    let mut iter = path.components();
    'success: {
        while let Some(comp) = iter.next() {
            match comp {
                std::path::Component::Prefix(_) => comps.push(comp),
                std::path::Component::RootDir | std::path::Component::CurDir => {
                    comps.push(comp);
                    break 'success;
                }
                std::path::Component::ParentDir | std::path::Component::Normal(_) => {
                    comps.push(std::path::Component::CurDir);
                    comps.push(comp);
                    break 'success;
                }
            }
        }
        // Iterator finished without any path component (besides Prefix).
        return Err(Error::EmptyPath);
    }

    // Add the rest of the components.
    comps.extend(iter);

    Ok(comps)
}

fn resolve_known_paths_impl(paths: Vec<Key<'_>>) -> Vec<PathBuf> {
    fn is_curr_dir(path: &[Component<'_>]) -> bool {
        match path {
            [Component::CurDir] => true,
            [Component::Prefix(_), Component::CurDir] => true,
            [] => unreachable!(),
            _ => false,
        }
    }

    let num_paths = paths.len();

    let mut all_subpaths = BTreeMap::new();

    for (orig_idx, path) in paths.into_iter().enumerate() {
        let first_slice_size = if let Component::Prefix(_) = &path[0] {
            // A prefix by itself is not a valid path, skip it
            2
        } else {
            1
        };

        for i in first_slice_size..path.len() {
            let key = path[0..i].to_owned();
            all_subpaths.insert(key, None);
        }
        all_subpaths.insert(path, Some(orig_idx));
    }

    // The resolved name of the parents in the currently processing stack:
    let mut parent_stack = Vec::new();

    let default = PathBuf::default();
    let mut result = vec![PathBuf::default(); num_paths];

    // Process paths in sorted order, so that previous paths are processed first:
    let mut iter = all_subpaths.into_iter().peekable();
    while let Some((path_components, orig_idx)) = iter.next() {
        // Try resolving this path
        match path_components.iter().collect::<PathBuf>().canonicalize() {
            Ok(path) => {
                parent_stack.resize(path_components.len() - 1, None);
                parent_stack.push(Some(path.clone()));
                if let Some(idx) = orig_idx {
                    assert_eq!(result[idx], default);
                    result[idx] = path;
                }
            }
            Err(_) => {
                // This directory and all its children are inaccessible, so we
                // are done with all of them.

                // Number of components in parent
                let num_comps = path_components.len();
                let resolved_path = if is_curr_dir(&path_components) {
                    // If current directory could not be resolved, we simply use
                    // it unresolved.
                    path_components.iter().collect()
                } else {
                    // Due to the order we process the subpaths, the parent of
                    // this path has been resolved and is on the stack.
                    parent_stack[num_comps - 2]
                        .as_ref()
                        .unwrap()
                        .join(path_components[num_comps - 1])
                };

                // Set the resolved path to all subentries:
                while let Some((key, orig_idx)) =
                    iter.next_if(|(key, _)| key.starts_with(&path_components))
                {
                    // The path of the entry is the path of the parent plus the
                    // components beyond the parent.
                    if let Some(idx) = orig_idx {
                        let mut path = resolved_path.clone();
                        path.extend(key[num_comps..].iter());
                        assert_eq!(result[idx], default);
                        result[idx] = path;
                    }
                }

                if let Some(idx) = orig_idx {
                    assert_eq!(result[idx], default);
                    result[idx] = resolved_path;
                }
            }
        }
    }

    assert!(result.iter().all(|e| *e != default));
    result
}

#[cfg(test)]
mod tests {
    use super::resolve_known_paths;
    use crate::Error;
    use std::{
        env::set_current_dir,
        fs::{create_dir_all, File},
        path::{Path, PathBuf},
        sync::Mutex,
    };
    use tempfile::Builder;

    /// All tests here relies on process-wide state current dir being fixed, so
    /// they can't run in parallel.
    static CURR_DIR_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn empty_path_error() {
        let dir = Builder::new().prefix("libflatview-test").tempdir().unwrap();
        let _g = CURR_DIR_MUTEX.lock().unwrap();
        set_current_dir(dir).unwrap();

        let paths = ["ddd/aaa", "ddd/bbb", "", "ddd/ccc"].map(|s| Path::new(s));

        assert!(matches!(resolve_known_paths(paths), Err(Error::EmptyPath)));
    }

    #[test]
    fn resolve_current_dir() {
        let dir = Builder::new().prefix("libflatview-test").tempdir().unwrap();
        let _g = CURR_DIR_MUTEX.lock().unwrap();
        set_current_dir(&dir).unwrap();
        let abs_dir = dir.path().canonicalize().unwrap();

        let paths = ["ddd/aaa", "./ddd/bbb", "abc/xyz", "ddd/./ccc"].map(|s| Path::new(s));

        let resolved = resolve_known_paths(paths).unwrap();

        let expected = ["ddd/aaa", "ddd/bbb", "abc/xyz", "ddd/ccc"];
        for (res, orig) in resolved.into_iter().zip(expected.into_iter()) {
            assert_eq!(res, abs_dir.join(orig));
        }
    }

    #[test]
    fn resolve_some_existing_files() {
        let dir = Builder::new().prefix("libflatview-test").tempdir().unwrap();
        let _g = CURR_DIR_MUTEX.lock().unwrap();
        set_current_dir(&dir).unwrap();
        let abs_dir = dir.path().canonicalize().unwrap();

        create_dir_all("aaa/aaa").unwrap();
        create_dir_all("aaa/ccc").unwrap();
        File::create("aaa/ccc/aaa").unwrap();

        let paths = [
            "aaa/aaa/aaa",
            "aaa/aaa/bbb",
            "aaa/bbb/aaa",
            "aaa/bbb/bbb",
            "aaa/aaa/../ccc/aaa",
            "aaa/aaa/../ccc/bbb",
            "aaa/bbb/../ccc/ccc",
            "aaa/bbb/../ccc/ddd",
            "aaa/aaa/../ddd/aaa",
            "aaa/bbb/../ddd/bbb",
        ]
        .map(|s| Path::new(s));

        let resolved = resolve_known_paths(paths).unwrap();

        let expected = [
            "aaa/aaa/aaa",
            "aaa/aaa/bbb",
            "aaa/bbb/aaa",
            "aaa/bbb/bbb",
            "aaa/ccc/aaa",
            "aaa/ccc/bbb",
            "aaa/bbb/../ccc/ccc",
            "aaa/bbb/../ccc/ddd",
            "aaa/ddd/aaa",
            "aaa/bbb/../ddd/bbb",
        ];
        for (res, orig) in resolved.into_iter().zip(expected.into_iter()) {
            assert_eq!(res, abs_dir.join(orig));
        }
    }

    #[test]
    fn resolve_absolute_and_relative() {
        let work_dir = Builder::new().prefix("libflatview-test").tempdir().unwrap();
        let _g = CURR_DIR_MUTEX.lock().unwrap();
        set_current_dir(&work_dir).unwrap();
        let work_abs_dir = work_dir.path().canonicalize().unwrap();

        let alt_dir = Builder::new().prefix("libflatview-test").tempdir().unwrap();
        let alt_abs_dir = alt_dir.path().canonicalize().unwrap();

        let paths = [
            PathBuf::from("./aaa"),
            PathBuf::from("bbb"),
            work_abs_dir.join("ccc"),
            alt_abs_dir.join("ddd"),
        ];

        let expected = [
            PathBuf::from("aaa"),
            PathBuf::from("bbb"),
            PathBuf::from("ccc"),
            alt_abs_dir.join("ddd"),
        ];

        let resolved = resolve_known_paths(paths.iter().map(|p| p.as_path())).unwrap();

        for (res, orig) in resolved.into_iter().zip(expected.into_iter()) {
            assert_eq!(res, work_abs_dir.join(orig));
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_unix_symbolic_links() {
        let work_dir = Builder::new().prefix("libflatview-test").tempdir().unwrap();
        let _g = CURR_DIR_MUTEX.lock().unwrap();
        set_current_dir(&work_dir).unwrap();
        let work_abs_dir = work_dir.path().canonicalize().unwrap();

        create_dir_all("aaa/bbb").unwrap();
        std::os::unix::fs::symlink(work_abs_dir.join("aaa/bbb"), "ccc").unwrap();

        let paths = ["ccc/../ddd"];
        let expected = work_abs_dir.join("aaa/ddd");

        let [resolved] = &resolve_known_paths(paths.iter().map(|p| Path::new(p))).unwrap()[..] else {
            panic!();
        };

        assert_eq!(*resolved, expected);
    }
}

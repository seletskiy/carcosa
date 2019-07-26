package main

func sync(repo *repo, remote string, ns string, auths auths) error {
	err := repo.pull(remote, refspec(ns), auths)
	if err != nil {
		return err
	}

	refs, err := repo.list(ns)
	if err != nil {
		return err
	}

	var (
		thys = map[string]ref{}
		ours = map[string]ref{}
		adds = map[string]ref{}
		dels = map[string]ref{}
	)

	for _, ref := range refs {
		switch {
		case ref.is(addition):
			adds[ref.token().name] = ref
		case ref.is(deletion):
			dels[ref.token().name] = ref
		case ref.is(external):
			thys[ref.token().name] = ref
		default:
			ours[ref.token().name] = ref
		}
	}

	for token, ref := range adds {
		err := repo.delete(ref)
		if err != nil {
			return err
		}

		thys[token] = ref.as(external)

		err = repo.update(thys[token])
		if err != nil {
			return err
		}
	}

	if len(thys) != 0 {
		for token, ref := range dels {
			err := repo.delete(ref)
			if err != nil {
				return err
			}

			if ref, ok := thys[token]; ok {
				err := repo.delete(ref)
				if err != nil {
					return err
				}

				delete(thys, token)
			}
		}

		err = repo.push(remote, refspec(ns), auths)
		if err != nil {
			return err
		}
	}

	for token, ref := range ours {
		if _, ok := thys[token]; !ok {
			err := repo.delete(ref)
			if err != nil {
				return err
			}
		}
	}

	for token, ref := range thys {
		if _, ok := ours[token]; !ok {
			err := repo.update(ref.token())
			if err != nil {
				return err
			}
		}

		err = repo.delete(ref)
		if err != nil {
			return err
		}
	}

	return nil
}

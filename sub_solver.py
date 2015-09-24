#!/usr/bin/python3.4

"""A cryptogram substitution-cipher solver."""

import argparse
import re
import functools
from copy import copy
from collections import (defaultdict, namedtuple, Counter)
from operator import itemgetter

__version__ = '0.0.1'


class NoSolutionException(Exception):
    pass


@functools.lru_cache()
def hash_word(word):
    """Hashes a word into its similarity equivalent.

    MXM becomes 010, ASDF becomes 0123, AFAFA becomes 01010, etc.
    """

    seen = dict()
    out = list()
    i = 0
    for c in word:
        if c not in seen:
            seen[c] = str(i)
            i += 1
        out.append(seen[c])
    return ''.join(out)


class Corpus(object):
    """Manages a corpus of words sorted by frequency descending."""

    def __init__(self, corpus_filename):
        self._hash_dict = defaultdict(list)
        with open(corpus_filename) as fp:
            for word in fp:
                _word = word.strip()
                self._hash_dict[hash_word(_word)].append(_word)

    def find_candidates(self, input_word):
        """Finds words in the corpus that could match the given word in
           ciphertext.

        For example, MXM would match wow but not cat, and cIF would match cat
        but not bat. Uppercase letters indicate ciphertext letters and lowercase
        letters indicate plaintext letters.

        Args:
            inputWord: The word to search for. Can be mixed uppercase/lowercase.
        """

        input_word_hash = hash_word(input_word)
        hash_matches = self._hash_dict[input_word_hash]

        candidates = list()
        for word in hash_matches:
            for candidate_char, input_char in zip(word, input_word):
                if input_char.islower() or input_char == "'" or candidate_char == "'":
                    if input_char != candidate_char:
                        break  # invalidate
            else:  # run this block if no break occurred i.e word is not invalidated
                candidates.append(word)

        return candidates


class SubSolver(object):
    """Solves substitution ciphers."""

    def __init__(self, ciphertext, corpus_filename, verbose=False):
        """Initializes the solver.

        Args:
            ciphertext: The ciphertext to solve.
            corpusFilename: The filename of the corpus to use.
            verbose: Print out intermediate steps.
        """
        self._corpus = Corpus(corpus_filename)
        self._translations = list()
        self.ciphertext = ciphertext.upper()
        self.verbose = verbose

    def best_cipher(self, remaining_words, trans):
        candidates_weight = 10.0
        coverage_weight = 1.0

        translated_words = [word.translate(trans) for word in remaining_words]
        candidate_lists =  [self._corpus.find_candidates(word) for word in translated_words]

        max_candidate_len = max(len(candidates) for candidates in candidate_lists)
        char_count = Counter(char for char in ''.join(translated_words) if char.isupper())
        total_char_count = sum(char_count.values())
        Result = namedtuple('Result', 'cipher_val cipher_word candidates n_candidates covered')
        best = Result(-1, 'dummy', [], 0, 0)

        for (candidates, cipher_word, translated_word) in zip(candidate_lists, remaining_words, translated_words):
            covered = sum(char_count[char] for char in set(translated_word) if char.isupper())
            coverage = covered / total_char_count
            n_candidates = len(candidates)
            candidate_len = ((max_candidate_len - n_candidates) / max_candidate_len)
            cipher_value = coverage * candidate_len
            if cipher_value > best.cipher_val:
                best = Result(cipher_value, cipher_word, candidates, n_candidates, covered)

        return best

    def solve(self):
        """Solves the cipher passed to the solver.

        This function invokes the recursive solver multiple times, starting
        with a very strict threshold on unknown words (which could be proper
        nouns or words not in the dictionary). It then expands this out to a
        final threshold, after which it considers the cipher unsolvable.
        """

        words = re.sub(r'[^\w ]+', '', self.ciphertext).split()

        words.sort(key=lambda word: len(self._corpus._hash_dict[hash_word(word)]), reverse=True)
        Translation = namedtuple('Translation', 'trans solution')
        err = NoSolutionException('Solve loop not started?')
        for max_unknown_word_count in range(0, max(3, len(words) / 10)):
            try:
                for solution in self._recursive_solve(words, {}, 0, max_unknown_word_count):
                    trans = self._make_trans_from_dict(solution)
                    print('Solution found: {0}'.format(self.ciphertext.translate(trans)))
                    self._translations.append(Translation(trans, solution))
                break
            except NoSolutionException as err:
                if self.verbose:
                    print(err)
            except KeyboardInterrupt:
                break

        else:   # loop not breaked => no solution found. reraise latest error
            raise err

    def _recursive_solve(self, remaining_words, current_translation,
                         unknown_word_count, max_unknown_word_count):
        """Recursively solves the puzzle.

        The algorithm chooses the first word from the list of remaining words,
        then finds all words that could possibly match it using the current
        translation table and the corpus. For each candidate, it builds a new
        dict that assumes that that candidate is the correct word, then
        continues the recursive search. It also tries ignoring the current word
        in case it's a pronoun.

        Args:
            remainingWords: The list of remaining words to translate, in
                descending length order.
            currentTranslation: The current translation table for this recursive
                state.
            unknownWordCount: The current number of words it had to skip.
            maxUnknownWordCount: The maximum number before it gives up.

        Returns:
            A dict that translates the ciphertext, or None if it could not find
            one.
        """

        trans = self._make_trans_from_dict(current_translation)

        if self.verbose:
            print(self.ciphertext.translate(trans))

        if not remaining_words:  # remaining words is empty. we're done!
            yield current_translation
            raise StopIteration()

        best = self.best_cipher(remaining_words, trans)
        if best.n_candidates == 0:
            raise NoSolutionException()
        cipher_word = best.cipher_word
        candidates = best.candidates
        remaining_words.remove(cipher_word)

        best_translations = list()

        for candidate in candidates:
            new_trans = dict(current_translation)
            translated_plaintext_chars = set(current_translation.values())
            for cipher_char, plaintext_char in zip(cipher_word, candidate):
                # This translation is bad if it tries to translate a ciphertext
                # character we haven't seen to a plaintext character we already
                # have a translation for.
                if cipher_char not in current_translation and plaintext_char in translated_plaintext_chars:
                    break
                new_trans[cipher_char] = plaintext_char
            else:  # code is reached if no break occurred => good translation
                _trans = self._make_trans_from_dict(new_trans)
                best = self.best_cipher(remaining_words, _trans)
                if best.n_candidates != 0 or len(remaining_words) == 0:
                    best_translations.append((new_trans, best.n_candidates, best.covered))

        if False:#best_translations:
            max_n_candidates = max(item[1] for item in best_translations) + 1
            max_covered = max(item[2] for item in best_translations) + 1
            best_translations.sort(key=lambda item: (max_n_candidates - item[1])/max_n_candidates + item[2]/max_covered, reverse=True)

        for trans, _, _ in best_translations:
            try:
                for sol in self._recursive_solve(remaining_words,
                                                 trans, unknown_word_count,
                                                 max_unknown_word_count):
                    yield sol
            except NoSolutionException:
                pass

        # If code is reached none of the candidates could produce valid result for the current cipher word
        # Try not using the candidates and skipping this word, because it
        # might not be in the corpus if it's a proper noun.

        if unknown_word_count >= max_unknown_word_count:  # We cannot skip anymore words than we already have
            remaining_words.append(cipher_word)     # Re-append cipher_word
            raise NoSolutionException(
                'Reached limit of {0} skipped words. \n best translation:'.format(unknown_word_count,
                                                                                  current_translation))
        try:
            for sol in self._recursive_solve(remaining_words,
                                         current_translation,
                                         unknown_word_count + 1,
                                         max_unknown_word_count):
                yield sol
        except NoSolutionException:
            remaining_words.append(cipher_word)     # Re-append cipher_word
            raise

    @staticmethod
    def _make_trans_from_dict(translations):
        """Takes a translation dictionary and returns a string fit for use with
           string.translate()."""

        from_str = translations.keys()
        to_str = translations.values()
        return str.maketrans(''.join(from_str), ''.join(to_str))

    def print_report(self):
        """Prints the result of the solve process."""

        if not self._translations:
            print('Failed to translate ciphertext.')
            return

        self._translations.sort(key=lambda item: len(item.solution), reverse=False)
        print('Plaintext:')
        for i, (trans, solution) in enumerate(self._translations):
            plaintext = self.ciphertext.translate(trans)
            print(str(i) + ':\t' + plaintext)

        if len(self._translations) > 1:
            i = int(input('which solution so you want?: '))

        print('Ciphertext:')
        print(self.ciphertext, '\n')

        trans, solution = self._translations[i]
        plaintext = self.ciphertext.translate(trans)

        print('Plaintext:')
        print(plaintext, '\n')

        print('Substitutions:')
        items = [key + ' -> ' + word for key, word in solution.items()]
        items.sort()
        i = 0
        for item in items:
            print(item + ' ', )
            if i % 5 == 4:
                print('')
            i += 1


def main():
    """Main entry point."""

    print('SubSolver v' + __version__ + '\n')

    parser = argparse.ArgumentParser(
        description='Solves substitution ciphers.')
    parser.add_argument('input_text',
                        help='A file containing the ciphertext.')

    parser.add_argument('-c', metavar='corpus', required=False,
                        default='corpus.txt',
                        help='Filename of the word corpus.')
    parser.add_argument('-v', action='store_true',
                        help='Verbose mode.')


    args = parser.parse_args()

    try:
        ciphertext = open(args.input_text).read().strip()
    except IOError as err:
        print('No file {0} found. using it as ciphertext'.format(args.input_text))
        ciphertext = args.input_text
    solver = SubSolver(ciphertext, args.c, args.v)
    solver.solve()
    solver.print_report()


if __name__ == '__main__':
    main()

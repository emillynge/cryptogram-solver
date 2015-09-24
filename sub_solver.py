#!/usr/bin/python3.4

"""A cryptogram substitution-cipher solver."""

import argparse
import re
import functools
from collections import defaultdict

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
        with open(corpus_filename) as fp:
            word_list = fp.read().splitlines()

        self._hash_dict = defaultdict(list)
        for word in word_list:
            self._hash_dict[hash_word(word)].append(word)

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
        self._translation = dict()
        self.ciphertext = ciphertext.upper()
        self.verbose = verbose

    def solve(self):
        """Solves the cipher passed to the solver.

        This function invokes the recursive solver multiple times, starting
        with a very strict threshold on unknown words (which could be proper
        nouns or words not in the dictionary). It then expands this out to a
        final threshold, after which it considers the cipher unsolvable.
        """

        words = re.sub(r'[^\w ]+', '', self.ciphertext).split()
        words.sort(key=lambda word: -len(word))

        err = NoSolutionException('Solve loop not started?')
        for max_unknown_word_count in range(0, max(3, len(words) / 10)):
            try:
                solution = self._recursive_solve(words, {}, 0,
                                                 max_unknown_word_count)
            except NoSolutionException as err:
                if self.verbose:
                    print(err)
            else:
                self._translation = solution
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
            return current_translation

        cipher_word = remaining_words.pop()
        candidates = self._corpus.find_candidates(cipher_word.translate(trans))

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
                try:
                    return self._recursive_solve(remaining_words,
                                                 new_trans, unknown_word_count,
                                                 max_unknown_word_count)
                except NoSolutionException:
                    pass

        # If code is reached none of the candidates could produce valid result for the current cipher word
        # Try not using the candidates and skipping this word, because it
        # might not be in the corpus if it's a proper noun.

        if unknown_word_count >= max_unknown_word_count:  # We cannot skip anymore words than we already have
            raise NoSolutionException(
                'Reached limit of {0} skipped words. \n best translation:'.format(unknown_word_count,
                                                                                  current_translation))

        return self._recursive_solve(remaining_words,
                                     current_translation,
                                     unknown_word_count + 1,
                                     max_unknown_word_count)

    @staticmethod
    def _make_trans_from_dict(translations):
        """Takes a translation dictionary and returns a string fit for use with
           string.translate()."""

        from_str = translations.keys()
        to_str = translations.values()
        return str.maketrans(''.join(from_str), ''.join(to_str))

    def print_report(self):
        """Prints the result of the solve process."""

        if not self._translation:
            print('Failed to translate ciphertext.')
            return

        plaintext = self.ciphertext.translate(SubSolver._make_trans_from_dict(self._translation))
        print('Ciphertext:')
        print(self.ciphertext, '\n')
        print('Plaintext:')
        print(plaintext, '\n')

        print('Substitutions:')
        items = [key + ' -> ' + word for key, word in self._translation.items()]
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
        print(err)
        return

    solver = SubSolver(ciphertext, args.c, args.v)
    solver.solve()
    solver.print_report()


if __name__ == '__main__':
    main()

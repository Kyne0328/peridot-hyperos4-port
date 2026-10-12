import unittest
from classify_delta import parse,Policy
class TestSets(unittest.TestCase):
 def fixture(self):
  p=Policy.__new__(Policy);p.types={'a','b','c'};p.alias={'alias_a':'a'};p.attrnames={'empty'};p.compdefs={'domain':['a','b','c']};p.source_defs={'mixed':[['and',['domain'],['not',['a']]],['and',['domain'],['not',['b']]]],'only_b':[['and',['domain'],['not',['a','c']]]]};p.cache={};p.active=set();return p
 def test_parse(self):self.assertEqual(parse('(allow a self (file (read write)))'),['allow','a','self',['file',['read','write']]])
 def test_union_and_not(self):
  p=self.fixture();self.assertEqual(p.members('mixed'),{'a','b','c'});self.assertEqual(p.members('only_b'),{'b'});self.assertEqual(p.members('empty'),set());self.assertEqual(p.members('alias_a'),{'a'})
 def test_unknown_is_not_silent(self):
  with self.assertRaises(ValueError):self.fixture().members('unknown')
if __name__=='__main__':unittest.main()

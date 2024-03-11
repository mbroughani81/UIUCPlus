# Running script
You should have [babashka](https://github.com/babashka/babashka) installed on system.

Change directory to project root and run script with:
```bash
bb scripts/gen_randoop_tests.clj
```

# Config structure

```
{
  "mutations": [
    {
      "mutant_number": 1,                                                   
      "id": "codet5-base.jackson-dataformat-xml.mid-54.idx-43346.3.mutant", <- the branch name that the mutant resides on
      "directory": "jackson-dataformat-xml",                                <- directory of the project where mutant changed.
      "commands": []                                                        <- list of command that will be executed in each mutant directory.
                                                                               You can access the id in this command with <ID>.
                                                                               To check if the test result was successful or not, use "<CHECK-IF-MUTATION-IS-BUGGY>"
                                                                               in the line after running the test for mutant
    }
}

```

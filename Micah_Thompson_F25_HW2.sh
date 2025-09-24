#Name: Micah Thompson
#CS 4350 - Unix Systems Programming
#Section Number: 001
#Assignment Number: 2
#Due Date: 09/22/2025 No Later Than 5:15pm

#!/usr/bin/env bash
set -euo pipefail

USAGE="Error: There Must Be 3 Integer Values
Example: $(basename "$0") <int1> <int2> <int3>"

#Help Flag
if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "$USAGE"
  exit 0
fi

#Require Exactly 3 Args
if [[ $# -ne 3 ]]; then
  echo "$USAGE" >&2
  exit 2
fi

# Validate integers (supports optional + / - signs)
int_re='^[+-]?[0-9]+$'
for arg in "$@"; do
  if ! [[ $arg =~ $int_re ]]; then
    echo "Error: '$arg' is not an integer." >&2
    echo "$USAGE" >&2
    exit 2
  fi
done

a=$1
b=$2
c=$3

# 2 Finding the Smallest
smallest=$a
(( b < smallest )) && smallest=$b
(( c < smallest)) && smallest=$c

# 3 Finding the Largest
largest=$a
(( b > largest )) && largest=$b
(( c > largest )) && largest=$c

# 4/5 Sum and Product
sum=$(( a + b + c ))
prod=$(( a * b * c ))

# 6 Finding Average
average=$(( sum / 3 ))

# 7 Squared Integers
a2=$(( a * a ))
b2=$(( b * b ))
c2=$(( c * c ))

#8 Positive, Negative, Zero
if (( a > 0 )); then
    asign='positive'
elif (( a < 0 )); then
    asign='negative'
else
    asign='zero'
fi
if (( b > 0 )); then
    bsign='positive'
elif (( b < 0 )); then
    bsign='negative'
else
    bsign='zero'
fi
if (( c > 0 )); then
    csign='positive'
elif (( c < 0 )); then
    csign='negative'
else
    csign='zero'
fi


echo "Your chosen integers: $a, $b, $c"
echo "Smallest Integer: $smallest "
echo "Largest Integer: $largest"
echo "Sum: $sum"
echo "Product: $prod"
echo "Average: $average"
echo "Squared: $a * $a = $a2, $b * $b = $b2, $c * $c = $c2"
echo "Signs: $asign, $bsign, $csign"

# 9 Odd or Even
printf "Odd or Even: \n"
for arg in "$@"; do
    if (( arg % 2 == 0 )); then
        echo "$arg is Even "
    else
        echo "$arg is Odd "
    fi
done

# 10 Even Numbers b/w 1 and 1st Argument
printf '\n'
printf "Even Numbers b/w 1 and the 1st Argument: \n"
if (( a>0 )); then
    for(( i=2; i<=a; i+=2 )); do
        echo "$i "
    done
else
    start=$(( (a % 2 == 0) ? a : a + 1))
    for (( i=start; i<=1; i+=2)); do
        echo "$i "
    done
fi

# 11 Odd Numbers b/w 1 and 2nd Argument
printf '\n'
printf "Odd Numbers b/w 1 and 2nd Argument: \n"
if (( b > 0 )); then
  for (( i=1; i<=b; i+=2 )); do
    echo "$i "
  done
elif (( b < 0 )); then
  start=$(( (b % 2 != 0) ? b : b + 1 ))
  for (( i=start; i<=1; i+=2 )); do
    echo "$i "
  done
fi

# 12 Factorial of Last Integer Argument
printf '\n'
printf "Factorial of $c: "
if (( c<0 )); then
    printf "Error: Integer is Negative"
else
    fact=1
    for (( i=2; i<=c; i++ )); do
        fact=$(( fact * i ))
    done
    printf "$fact"
fi

# 13 Determine Second Integer Prime
printf '\n'
if (( b < 0 )); then
    # Making the number positive if negative
    b=$(( b * -1))
fi
is_prime=1
if (( b % 2 == 0 )); then
    (( b == 2 )) || is_prime=0
else
    i=3
    while (( i * i <= b )); do
      if (( b % i == 0 )); then
        is_prime=0
        break
      fi
      i=$(( i + 2 ))
done
fi

if (( is_prime )); then
    echo "$b is prime"
else
    echo "$b is not prime"
fi

#printf "Most Updated As of 09/22/2025"
printf "\n End of Script\n"

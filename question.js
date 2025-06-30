const readline = require('readline');

function getUserQuestion() {
  return new Promise(resolve => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    rl.question('Enter your question: ', q => {
      rl.close();
      resolve(q);
    });
  });
}

async function main() {
  const userQuestion = await getUserQuestion();
  console.log('Question stored:', userQuestion);
}

main();


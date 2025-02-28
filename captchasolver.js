const fs = require('fs');
const { createCanvas, loadImage } = require('canvas');

// Assuming this will be populated with your bitmap data
// This should be the same data used in the browser version
const bitmaps = require('./bitmaps.json');

const captcha_parse = (imgarr) => {
  let captcha = "";
  for (let x = 1; x < 44; x++) {
    for (let y = 1; y < 179; y++) {
      const condition1 =
        imgarr[x][y - 1] === 255 &&
        imgarr[x][y] === 0 &&
        imgarr[x][y + 1] === 255;
      const condition2 =
        imgarr[x - 1][y] === 255 &&
        imgarr[x][y] === 0 &&
        imgarr[x + 1][y] === 255;
      const condition3 = imgarr[x][y] !== 255 && imgarr[x][y] !== 0;
      if (condition1 || condition2 || condition3) {
        imgarr[x][y] = 255;
      }
    }
  }
  for (let j = 30; j < 181; j += 30) {
    let matches = [];
    const chars = "123456789ABCDEFGHIJKLMNPQRSTUVWXYZ";
    for (let i = 0; i < chars.length; i++) {
      let match = 0;
      let black = 0;
      const ch = chars.charAt(i);
      const mask = bitmaps[ch];
      for (let x = 0; x < 32; x++) {
        for (let y = 0; y < 30; y++) {
          let y1 = y + j - 30;
          let x1 = x + 12;
          if (imgarr[x1][y1] == mask[x][y] && mask[x][y] == 0) {
            match += 1;
          }
          if (mask[x][y] == 0) {
            black += 1;
          }
        }
      }
      const perc = match / black;
      matches.push([perc, ch]);
    }
    captcha += matches.reduce(
      function (a, b) {
        return a[0] > b[0] ? a : b;
      },
      [0, 0]
    )[1];
  }
  return captcha;
};

const pre_img = (img) => {
  let avg = 0;
  img.forEach((e) => e.forEach((f) => (avg += f)));
  avg /= 24 * 22;
  var bits = new Array(img.length);
  for (let i = 0; i < img.length; i += 1) {
    bits[i] = new Array(img[0].length);
    for (let j = 0; j < img[0].length; j += 1) {
      if (img[i][j] > avg) {
        bits[i][j] = 1;
      } else {
        bits[i][j] = 0;
      }
    }
  }
  return bits;
};

const saturation = (d) => {
  saturate = new Array(d.length / 4);
  for (let i = 0; i < d.length; i += 4) {
    min = Math.min(d[i], d[i + 1], d[i + 2]);
    max = Math.max(d[i], d[i + 1], d[i + 2]);
    saturate[i / 4] = Math.round(((max - min) * 255) / max);
  }
  var img = new Array(40);
  for (let i = 0; i < 40; i += 1) {
    img[i] = new Array(200);
    for (let j = 0; j < 200; j += 1) {
      img[i][j] = saturate[i * 200 + j];
    }
  }
  bls = new Array(6);
  for (let i = 0; i < 6; i += 1) {
    c = 0;
    d = 0;
    x1 = (i + 1) * 25 + 2;
    y1 = 7 + 5 * (i % 2) + 1;
    x2 = (i + 2) * 25 + 1;
    y2 = 35 - 5 * ((i + 1) % 2);
    bls[i] = img.slice(y1, y2).map((i) => i.slice(x1, x2));
  }
  return bls;
};

const flatten = (arr) => {
  var bits = new Array(arr.length * arr[0].length);
  for (let i = 0; i < arr.length; i += 1) {
    for (let j = 0; j < arr[0].length; j += 1) {
      bits[i * arr[0].length + j] = arr[i][j];
    }
  }
  return bits;
};

const mat_mul = (a, b) => {
  let x = a.length,
    z = a[0].length,
    y = b[0].length;
  let productRow = Array.apply(null, new Array(y)).map(
    Number.prototype.valueOf,
    0
  );
  let product = new Array(x);
  for (let p = 0; p < x; p++) {
    product[p] = productRow.slice();
  }
  for (let i = 0; i < x; i++) {
    for (let j = 0; j < y; j++) {
      for (let k = 0; k < z; k++) {
        product[i][j] += a[i][k] * b[k][j];
      }
    }
  }
  return product;
};

const mat_add = (a, b) => {
  let x = a.length;
  let c = new Array(x);
  for (let i = 0; i < x; i++) {
    c[i] = a[i] + b[i];
  }
  return c;
};

const max_soft = (a) => {
  var n = [...a];
  let s = 0;
  n.forEach((f) => {
    s += Math.exp(f);
  });
  for (let i = 0; i < a.length; i++) {
    n[i] = Math.exp(a[i]) / s;
  }
  return n;
};

const HEIGHT = 40;
const WIDTH = 200;

// Modified to accept a base64 image string
const solveCaptchaFromBase64 = async (base64String) => {
  try {
    // Create a temporary file to store the base64 image
    const imageData = base64String.split(',')[1]; // Remove the data:image/jpeg;base64, part if present
    const tempFilePath = './temp_captcha.jpg';
    fs.writeFileSync(tempFilePath, Buffer.from(imageData, 'base64'));

    // Now load the image from the file
    const img = await loadImage(tempFilePath);
    
    // Create a canvas and draw the image on it
    const canvas = createCanvas(WIDTH, HEIGHT);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, WIDTH, HEIGHT);
    
    // Get image data
    const imagePixels = ctx.getImageData(0, 0, WIDTH, HEIGHT);
    
    // Process using the method from the browser version
    const weights = bitmaps.weights;
    const biases = bitmaps.biases;
    const label_txt = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    
    let bls = saturation(imagePixels.data);
    let out = "";
    
    for (let i = 0; i < 6; i += 1) {
      bls[i] = pre_img(bls[i]);
      bls[i] = [flatten(bls[i])];
      bls[i] = mat_mul(bls[i], weights);
      bls[i] = mat_add(...bls[i], biases);
      bls[i] = max_soft(bls[i]);
      bls[i] = bls[i].indexOf(Math.max(...bls[i]));
      out += label_txt[bls[i]];
    }
    
    // Clean up the temporary file
    fs.unlinkSync(tempFilePath);
    
    return out;
  } catch (error) {
    console.error('Error solving CAPTCHA:', error);
    return null;
  }
};

// For direct image file processing
const solveCaptchaFromFile = async (imagePath) => {
  try {
    const img = await loadImage(imagePath);
    
    const canvas = createCanvas(WIDTH, HEIGHT);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, WIDTH, HEIGHT);
    
    const imagePixels = ctx.getImageData(0, 0, WIDTH, HEIGHT);
    
    const weights = bitmaps.weights;
    const biases = bitmaps.biases;
    const label_txt = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    
    let bls = saturation(imagePixels.data);
    let out = "";
    
    for (let i = 0; i < 6; i += 1) {
      bls[i] = pre_img(bls[i]);
      bls[i] = [flatten(bls[i])];
      bls[i] = mat_mul(bls[i], weights);
      bls[i] = mat_add(...bls[i], biases);
      bls[i] = max_soft(bls[i]);
      bls[i] = bls[i].indexOf(Math.max(...bls[i]));
      out += label_txt[bls[i]];
    }
    
    return out;
  } catch (error) {
    console.error('Error solving CAPTCHA from file:', error);
    return null;
  }
};

module.exports = {
  solveCaptchaFromBase64,
  solveCaptchaFromFile
};
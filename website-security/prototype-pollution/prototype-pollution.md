# Prototype Pollution

## Explanation

This vulnerability arises when JS functions recursively merges an object containing user-controlled properties into an existing object without first sanitising the keys.

Basically, properties can be injected with keys, for example with `__proto__`. This allows attackers to pollute the prototype with properties that contain harmful values, which can be abused. JS allows for the  modification, addition, or deletion of attributes at runtime, so functions can be changed to have different behaviours.

When Object prototypes are altered, all objects in the environment are affected. Here's one example:

```js
function Animal(animal) {
    this.animal = animal;
}
var pet = new Animal("Cat");
```

The above demonstrates how OOP is implemented in Javascript, using constructors to emulate class behaviour due to JS not supporting class support like Java. These are accessible through:

```js
pet.__proto__.__proto__;
Animal.__proto__.__proto__;
```

`__proto__` is a 'getter' function tah exposes teh value of the internal prototype of an object. It allows the object to be mutated as well. 

{% embed url="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto" %}

For our `pet` and `Animal` objects, properties can be added using this `__proto__` function. For example, I can add variables the class

```js
pet.__proto__._proto__.canBark = false;
```

The above adds a boolean variable, accessible through `pet.canBark`. Apart from variables, whole functions can be added:

```js
Animal.__proto__.__proto__.eatFood = function() { console.log ("Ate!"); };
```

Sometimes using `__proto__` is not allowed, so modifying a function's prototype is also possible:

```js
pet.prototype.canBark = false;
```

So the basis of Prototype Pollution is sort of manipulating the fact that JS allows for modifying attributes at runtime, and hence one can inject code or perform malicious actions.

## Exploitation

Since I can basically inject attributes into objects, unsanitised parameters taken from users in web applications can sometimes be used to manipulate stuff.

Suppose I have this bit of code:

```js
if (search.isValid) {
    return search;
}
else (
    console.log("fail");
)
```

I have to make `isValid` true. If I can inject `Object.prototype.isValid = true`, this would make ALL objects have an `isValid` variable set to true. The conditions of which JS needs to be abused are:

* Code needs to perform **recursive merge**
* Defines properties based on a path
* Cloning objects

Note that apart from variables and adding functions, existing functions can also be manipulated, such as using `__proto__.toString = ()=>{console.log("pwned")}` to manipulate the `toString()` function for an object.

Prototype pollution most commonly occurs with `Object.prototype` because it is a global variable that **affects all other objects**. Successful exploitation requires the following:

* Input that enables attackers to poison prototype objects (Source)
* A Javascript function or DOM element that enables RCE (sink)
* Property that is passed without proper filtering or sanitisation (Gadget).
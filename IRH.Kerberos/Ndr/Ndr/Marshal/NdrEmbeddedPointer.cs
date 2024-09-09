using System;

namespace IRH.Kerberos.Ndr.Marshal
{
    public class NdrEmbeddedPointer<T>
    {
        private T _value;

        private NdrEmbeddedPointer(T value)
        {
            _value = value;
        }

        public static implicit operator NdrEmbeddedPointer<T>(T value)
        {
            return new NdrEmbeddedPointer<T>(value);
        }

        public static implicit operator T(NdrEmbeddedPointer<T> pointer)
        {
            if (pointer == null)
            {
                return default;
            }
            return pointer._value;
        }

        public override string ToString()
        {
            return _value.ToString();
        }

        public T GetValue()
        {
            return _value;
        }

        internal static Tuple<NdrEmbeddedPointer<T>, Action> CreateDeferredReader(Func<T> unmarshal_func)
        {
            NdrEmbeddedPointer<T> ret = new NdrEmbeddedPointer<T>(default);
            return Tuple.Create(ret, new Action(() => ret._value = unmarshal_func()));
        }

        internal static Tuple<NdrEmbeddedPointer<T>, Action> CreateDeferredReader<U>(Func<U, T> unmarshal_func, U arg)
        {
            NdrEmbeddedPointer<T> ret = new NdrEmbeddedPointer<T>(default);
            return Tuple.Create(ret, new Action(() => ret._value = unmarshal_func(arg)));
        }

        internal static Tuple<NdrEmbeddedPointer<T>, Action> CreateDeferredReader<U, V>(Func<U, V, T> unmarshal_func, U arg, V arg2)
        {
            NdrEmbeddedPointer<T> ret = new NdrEmbeddedPointer<T>(default);
            return Tuple.Create(ret, new Action(() => ret._value = unmarshal_func(arg, arg2)));
        }
    }
}

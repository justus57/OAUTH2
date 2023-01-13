using System;

namespace NAV
{
    internal class NAV
    {
        private Uri uri;

        public NAV(Uri uri)
        {
            this.uri = uri;
        }

        public Func<object, object, object> BuildingRequest { get; internal set; }
    }
}